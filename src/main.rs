use chrono::Local;
use eframe::egui;
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
};
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

const MAGIC: &[u8] = b"INSECRETv2.0";

#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    version: String,
    count: usize,
    timestamp: String,
    encrypted: bool,
}

fn xor_crypt(data: &[u8], password: &str) -> Vec<u8> {
    if password.is_empty() {
        return data.to_vec();
    }
    let key = Sha256::digest(password.as_bytes());
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn compress_paths(paths: &[PathBuf]) -> io::Result<Vec<u8>> {
    let mut zip_buffer = Cursor::new(Vec::<u8>::new());
    {
        let mut zw = ZipWriter::new(&mut zip_buffer);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for path in paths {
            if path.is_dir() {
                let folder_name = path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or("folder")
                    .to_string();

                add_dir_to_zip(&mut zw, path, Path::new(&folder_name), options)?;
            } else if path.is_file() {
                let name = path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or("file")
                    .to_string();
                zw.start_file(name, options)?;
                let mut f = File::open(path)?;
                io::copy(&mut f, &mut zw)?;
            }
        }
        zw.finish()?;
    }

    // Match the Python implementation's outer zlib compression.
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(zip_buffer.get_ref())?;
    encoder.finish()
}

fn add_dir_to_zip(
    zw: &mut ZipWriter<&mut Cursor<Vec<u8>>>,
    root: &Path,
    prefix: &Path,
    options: SimpleFileOptions,
) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let p = entry.path();
        let rel_name = prefix.join(entry.file_name());

        if p.is_dir() {
            add_dir_to_zip(zw, &p, &rel_name, options)?;
        } else if p.is_file() {
            zw.start_file(rel_name.to_string_lossy().replace('\\', "/"), options)?;
            let mut f = File::open(&p)?;
            io::copy(&mut f, zw)?;
        }
    }
    Ok(())
}

fn decompress_data(data: &[u8], output_dir: &Path) -> io::Result<(usize, usize)> {
    fs::create_dir_all(output_dir)?;

    let decompressed = match flate2::read::ZlibDecoder::new(Cursor::new(data)).bytes().collect::<Result<Vec<_>, _>>() {
        Ok(v) => v,
        Err(_) => data.to_vec(),
    };

    let cursor = Cursor::new(decompressed);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(z) => z,
        Err(_) => {
            fs::write(output_dir.join("extracted_data.bin"), data)?;
            return Ok((1, 0));
        }
    };

    let mut files = 0usize;
    let mut folders = 0usize;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().replace('\\', "/");
        let out = output_dir.join(&name);

        // Prevent ZIP path traversal.
        let clean = Path::new(&name);
        if clean.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            continue;
        }

        if entry.is_dir() {
            fs::create_dir_all(&out)?;
            folders += 1;
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = File::create(&out)?;
            io::copy(&mut entry, &mut f)?;
            files += 1;
        }
    }

    Ok((files, folders))
}

fn embed_files(
    carrier: &Path,
    files: &[PathBuf],
    output: &Path,
    password: &str,
) -> Result<String, String> {
    if !carrier.exists() {
        return Err("Carrier file not found".into());
    }

    let valid: Vec<PathBuf> = files.iter().filter(|p| p.exists()).cloned().collect();
    if valid.is_empty() {
        return Err("No valid files to hide".into());
    }

    let carrier_data = fs::read(carrier).map_err(|e| e.to_string())?;
    let mut payload = compress_paths(&valid).map_err(|e| e.to_string())?;

    if !password.is_empty() {
        payload = xor_crypt(&payload, password);
    }

    let metadata = Metadata {
        version: "2.0".into(),
        count: valid.len(),
        timestamp: Local::now().to_rfc3339(),
        encrypted: !password.is_empty(),
    };

    let metadata_json = serde_json::to_vec(&metadata).map_err(|e| e.to_string())?;

    let mut out = File::create(output).map_err(|e| e.to_string())?;
    out.write_all(&carrier_data).map_err(|e| e.to_string())?;
    out.write_all(MAGIC).map_err(|e| e.to_string())?;
    out.write_all(&(metadata_json.len() as u32).to_le_bytes())
        .map_err(|e| e.to_string())?;
    out.write_all(&metadata_json).map_err(|e| e.to_string())?;
    out.write_all(&(payload.len() as u64).to_le_bytes())
        .map_err(|e| e.to_string())?;
    out.write_all(&payload).map_err(|e| e.to_string())?;

    let written = fs::read(output).map_err(|e| e.to_string())?;
    if written.len() < carrier_data.len() + MAGIC.len()
        || &written[..carrier_data.len()] != carrier_data.as_slice()
        || &written[carrier_data.len()..carrier_data.len() + MAGIC.len()] != MAGIC
    {
        return Err("Carrier verification failed".into());
    }

    Ok(format!(
        "EMBEDDING SUCCESSFUL\n\nOutput: {}\nTotal: {:,} bytes\nCarrier: {:,} bytes\nHidden: {:,} bytes\nEncrypted: {}\nCarrier check: PERFECT\nItems: {}",
        output.display(),
        written.len(),
        carrier_data.len(),
        payload.len(),
        if password.is_empty() { "No" } else { "Yes" },
        valid.len()
    ))
}

fn find_magic(data: &[u8]) -> Option<usize> {
    data.windows(MAGIC.len()).rposition(|w| w == MAGIC)
}

fn extract_files(
    stego: &Path,
    output_dir: &Path,
    password: &str,
) -> Result<String, String> {
    if !stego.exists() {
        return Err("Stego file not found".into());
    }

    let data = fs::read(stego).map_err(|e| e.to_string())?;
    let idx = find_magic(&data).ok_or("Not a valid Invisible Secrets file")?;
    let carrier = &data[..idx];
    let mut pos = idx + MAGIC.len();

    if pos + 4 > data.len() {
        return Err("Corrupted stego data (metadata size)".into());
    }
    let metadata_size = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    if pos + metadata_size > data.len() {
        return Err("Corrupted stego data (metadata)".into());
    }
    let metadata: Metadata =
        serde_json::from_slice(&data[pos..pos + metadata_size]).map_err(|e| e.to_string())?;
    pos += metadata_size;

    if pos + 8 > data.len() {
        return Err("Corrupted stego data (compressed size)".into());
    }
    let payload_size = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap()) as usize;
    pos += 8;

    if pos + payload_size > data.len() {
        return Err("Corrupted stego data (payload)".into());
    }

    let mut hidden = data[pos..pos + payload_size].to_vec();
    if metadata.encrypted || !password.is_empty() {
        hidden = xor_crypt(&hidden, password);
    }

    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
    let (files, folders) = decompress_data(&hidden, output_dir).map_err(|e| e.to_string())?;

    let ext = stego.extension().and_then(|x| x.to_str()).unwrap_or("");
    let carrier_name = if ext.is_empty() {
        "original_carrier".to_string()
    } else {
        format!("original_carrier.{ext}")
    };
    let carrier_path = output_dir.join(carrier_name);
    fs::write(&carrier_path, carrier).map_err(|e| e.to_string())?;

    Ok(format!(
        "EXTRACTION COMPLETE\n\nDirectory: {}\nFiles: {}\nFolders: {}\nCarrier: {}",
        output_dir.display(),
        files,
        folders,
        carrier_path.display()
    ))
}

fn analyze_file(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let idx = find_magic(&data).ok_or("No hidden data found")?;
    let carrier_size = idx;
    let mut pos = idx + MAGIC.len();

    if pos + 4 > data.len() {
        return Err("Corrupted stego data (metadata size)".into());
    }
    let metadata_size = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    if pos + metadata_size > data.len() {
        return Err("Corrupted stego data (metadata)".into());
    }
    let metadata: Metadata =
        serde_json::from_slice(&data[pos..pos + metadata_size]).map_err(|e| e.to_string())?;
    pos += metadata_size;

    if pos + 8 > data.len() {
        return Err("Corrupted stego data (compressed size)".into());
    }
    let hidden_size = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());

    Ok(format!(
        "HIDDEN DATA FOUND\n\nItems: {}\nHidden: {:,} bytes\nCarrier: {:,} bytes\nTotal: {:,} bytes\nEncrypted: {}",
        metadata.count,
        hidden_size,
        carrier_size,
        data.len(),
        if metadata.encrypted { "YES" } else { "NO" }
    ))
}

#[derive(Default)]
struct App {
    carrier: Option<PathBuf>,
    output: Option<PathBuf>,
    hidden: Vec<PathBuf>,
    stego: Option<PathBuf>,
    extract_dir: Option<PathBuf>,
    analyze: Option<PathBuf>,
    password: String,
    extract_password: String,
    status: String,
    embed_log: String,
    extract_log: String,
    analyze_log: String,
    tab: usize,
}

impl App {
    fn browse_file() -> Option<PathBuf> {
        FileDialog::new().pick_file()
    }

    fn browse_save() -> Option<PathBuf> {
        FileDialog::new().save_file()
    }

    fn browse_dir() -> Option<PathBuf> {
        FileDialog::new().pick_folder()
    }

    fn do_embed(&mut self) {
        let (Some(carrier), Some(output)) = (&self.carrier, &self.output) else {
            self.embed_log = "Please select a carrier and output file.".into();
            return;
        };
        self.status = "Embedding...".into();
        match embed_files(carrier, &self.hidden, output, &self.password) {
            Ok(msg) => {
                self.embed_log = msg;
                self.status = "Ready".into();
            }
            Err(e) => {
                self.embed_log = format!("Error: {e}");
                self.status = "Error".into();
            }
        }
    }

    fn do_extract(&mut self) {
        let (Some(stego), Some(dir)) = (&self.stego, &self.extract_dir) else {
            self.extract_log = "Please select a stego file and output directory.".into();
            return;
        };
        self.status = "Extracting...".into();
        match extract_files(stego, dir, &self.extract_password) {
            Ok(msg) => {
                self.extract_log = msg;
                self.status = "Ready".into();
            }
            Err(e) => {
                self.extract_log = format!("Error: {e}");
                self.status = "Error".into();
            }
        }
    }

    fn do_analyze(&mut self) {
        let Some(path) = &self.analyze else {
            self.analyze_log = "Please select a file to analyze.".into();
            return;
        };
        self.status = "Analyzing...".into();
        match analyze_file(path) {
            Ok(msg) => {
                self.analyze_log = msg;
                self.status = "Ready".into();
            }
            Err(e) => {
                self.analyze_log = format!("Error: {e}");
                self.status = "Error".into();
            }
        }
    }

    fn row_path(ui: &mut egui::Ui, label: &str, value: &mut Option<PathBuf>, save: bool) {
        ui.horizontal(|ui| {
            ui.label(label);
            let shown = value
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            ui.add_sized([520.0, 24.0], egui::TextEdit::singleline(&mut shown.clone()).interactive(false));
            if ui.button("Browse").clicked() {
                *value = if save { Self::browse_save() } else { Self::browse_file() };
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Invisible Secrets");
            ui.separator();

            ui.horizontal(|ui| {
                for (i, name) in ["Embed", "Extract", "Analyze"].iter().enumerate() {
                    if ui.selectable_label(self.tab == i, *name).clicked() {
                        self.tab = i;
                    }
                }
            });
            ui.separator();

            match self.tab {
                0 => {
                    ui.group(|ui| {
                        ui.label("Carrier file");
                        Self::row_path(ui, "", &mut self.carrier, false);
                    });

                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.label("Files / folders to hide");
                        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                            for p in &self.hidden {
                                ui.label(p.display().to_string());
                            }
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Add files").clicked() {
                                if let Some(files) = FileDialog::new().pick_files() {
                                    for p in files {
                                        if !self.hidden.contains(&p) {
                                            self.hidden.push(p);
                                        }
                                    }
                                }
                            }
                            if ui.button("Add folder").clicked() {
                                if let Some(p) = Self::browse_dir() {
                                    if !self.hidden.contains(&p) {
                                        self.hidden.push(p);
                                    }
                                }
                            }
                            if ui.button("Remove selected").clicked() && !self.hidden.is_empty() {
                                self.hidden.pop();
                            }
                        });
                    });

                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.label("Output & security");
                        Self::row_path(ui, "Output file:", &mut self.output, true);
                        ui.horizontal(|ui| {
                            ui.label("Password:");
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        });
                    });

                    if ui.button("Embed").clicked() {
                        self.do_embed();
                    }
                    ui.add(egui::TextEdit::multiline(&mut self.embed_log).desired_rows(7));
                }
                1 => {
                    ui.group(|ui| {
                        ui.label("Stego file");
                        Self::row_path(ui, "", &mut self.stego, false);
                    });
                    ui.add_space(8.0);
                    ui.group(|ui| {
                        ui.label("Output directory");
                        ui.horizontal(|ui| {
                            let mut shown = self.extract_dir.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                            ui.add_sized([520.0, 24.0], egui::TextEdit::singleline(&mut shown).interactive(false));
                            if ui.button("Browse").clicked() {
                                self.extract_dir = Self::browse_dir();
                            }
                        });
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        ui.add(egui::TextEdit::singleline(&mut self.extract_password).password(true));
                    });
                    if ui.button("Extract").clicked() {
                        self.do_extract();
                    }
                    ui.add(egui::TextEdit::multiline(&mut self.extract_log).desired_rows(8));
                }
                _ => {
                    ui.group(|ui| {
                        ui.label("File to analyze");
                        Self::row_path(ui, "", &mut self.analyze, false);
                    });
                    ui.add_space(8.0);
                    if ui.button("Analyze").clicked() {
                        self.do_analyze();
                    }
                    ui.add(egui::TextEdit::multiline(&mut self.analyze_log).desired_rows(10));
                }
            }

            ui.separator();
            ui.label(format!("Status: {}", self.status));
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([850.0, 650.0])
            .with_min_inner_size([750.0, 550.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Invisible Secrets",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}
