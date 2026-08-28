#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::{self, File};
use std::io::{Read, Write, Cursor};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use sha2::{Sha256, Digest};
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::ZipArchive;
use serde::{Serialize, Deserialize};
use eframe::egui;

const MAGIC_HEADER: &[u8] = b"INSECRETv2.0";

#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    version: String,
    count: usize,
    timestamp: String,
    encrypted: bool,
}

// ---- ஸ்டெகனோகிராபி முக்கிய லாஜிக் (Core Logic) ----
fn xor_crypt(data: &[u8], password: &str) -> Vec<u8> {
    if password.is_empty() { return data.to_vec(); }
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key = hasher.finalize();
    let key_len = key.len();
    data.iter().enumerate().map(|(i, &byte)| byte ^ key[i % key_len]).collect()
}

fn compress_data(filepaths: &[PathBuf]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let buf = Vec::new();
    let mut cursor = Cursor::new(buf);
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for path in filepaths {
            if !path.exists() { continue; }
            if path.is_dir() {
                let folder_name = path.file_name().unwrap().to_string_lossy();
                for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                    let full_path = entry.path();
                    if full_path.is_file() {
                        let rel_path = full_path.strip_prefix(path)?;
                        let arcname = format!("{}/{}", folder_name, rel_path.display());
                        zip.start_file(arcname, options)?;
                        let mut f = File::open(full_path)?;
                        let mut buffer = Vec::new();
                        f.read_to_end(&mut buffer)?;
                        zip.write_all(&buffer)?;
                    }
                }
            } else {
                let file_name = path.file_name().unwrap().to_string_lossy();
                zip.start_file(file_name, options)?;
                let mut f = File::open(path)?;
                let mut buffer = Vec::new();
                f.read_to_end(&mut buffer)?;
                zip.write_all(&buffer)?;
            }
        }
        zip.finish()?;
    }
    let zip_bytes = cursor.into_inner();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&zip_bytes)?;
    Ok(encoder.finish()?)
}

fn decompress_data(compressed_data: &[u8], output_dir: &str) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed = Vec::new();
    let zip_bytes = match decoder.read_to_end(&mut decompressed) {
        Ok(_) => decompressed,
        Err(_) => compressed_data.to_vec(),
    };
    let mut file_count = 0;
    let mut folder_count = 0;
    let cursor = Cursor::new(zip_bytes);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(arch) => arch,
        Err(_) => {
            let single_file = Path::new(output_dir).join("extracted_data.bin");
            let mut f = File::create(&single_file)?;
            f.write_all(&compressed_data)?;
            return Ok((1, 0));
        }
    };
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => Path::new(output_dir).join(path),
            None => continue,
        };
        if file.name().endswith('/') {
            fs::create_dir_all(&outpath)?;
            folder_count += 1;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() { fs::create_dir_all(p)?; folder_count += 1; }
            }
            let mut outfile = File::create(&outpath)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            outfile.write_all(&buffer)?;
            file_count += 1;
        }
    }
    Ok((file_count, folder_count))
}

// ---- GUI அப்ளிகேஷன் கட்டமைப்பு (GUI App Structure) ----
struct InvisibleSecretsApp {
    // Embed செய்யத் தேவையானவை
    carrier_path: String,
    files_to_hide: Vec<PathBuf>,
    output_path: String,
    password_embed: String,
    // Extract செய்யத் தேவையானவை
    stego_path: String,
    extract_dir: String,
    password_extract: String,
    // அவுட்புட் மெசேஜ் லாக்
    status_text: String,
}

impl Default for InvisibleSecretsApp {
    fn default() -> Self {
        Self {
            carrier_path: String::new(),
            files_to_hide: Vec::new(),
            output_path: String::new(),
            password_embed: String::new(),
            stego_path: String::new(),
            extract_dir: String::new(),
            password_extract: String::new(),
            status_text: "Ready - Select fields to start embedding or extracting.".to_string(),
        }
    }
}

impl eframe::App for InvisibleSecretsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // அழகான டார்க் தீம் செட்டிங்
        ctx.set_visuals(egui::Visuals::dark());

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🚀 INVISIBLE SECRETS v2.0 (RUST GUI)");
            ui.separator();

            // 1. EMBED PANEL
            egui::Window::new("Embed Mode (Hide Files)").resizable(false).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Carrier File:");
                    ui.text_edit_singleline(&mut self.carrier_path);
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.carrier_path = path.display().to_string();
                        }
                    }
                });

                ui.vertical(|ui| {
                    ui.label("Files/Folders to Hide:");
                    for path in &self.files_to_hide {
                        ui.label(format!("• {}", path.display()));
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Add Files").clicked() {
                            if let Some(files) = rfd::FileDialog::new().pick_files() {
                                self.files_to_hide.extend(files);
                            }
                        }
                        if ui.button("Clear List").clicked() {
                            self.files_to_hide.clear();
                        }
                    });
                });

                ui.horizontal(|ui| {
                    ui.label("Output File:");
                    ui.text_edit_singleline(&mut self.output_path);
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new().save_file() {
                            self.output_path = path.display().to_string();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Password (Optional):");
                    ui.text_edit_password(&mut self.password_embed);
                });

                if ui.button("🚀 EMBED NOW").clicked() {
                    if self.carrier_path.is_empty() || self.files_to_hide.is_empty() || self.output_path.is_empty() {
                        self.status_text = "❌ Error: Missing inputs for embedding!".to_string();
                    } else {
                        match fs::read(&self.carrier_path) {
                            Ok(carrier_data) => {
                                match compress_data(&self.files_to_hide) {
                                    Ok(compressed) => {
                                        let final_payload = xor_crypt(&compressed, &self.password_embed);
                                        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs().to_string();
                                        let meta = Metadata {
                                            version: "2.0".to_string(),
                                            count: self.files_to_hide.len(),
                                            timestamp: now,
                                            encrypted: !self.password_embed.is_empty(),
                                        };
                                        let meta_json = serde_json::to_vec(&meta).unwrap();
                                        let meta_size = meta_json.len() as u32;
                                        let comp_size = final_payload.len() as u64;

                                        match File::create(&self.output_path) {
                                            Ok(mut out_file) => {
                                                let _ = out_file.write_all(&carrier_data);
                                                let _ = out_file.write_all(MAGIC_HEADER);
                                                let _ = out_file.write_all(&meta_size.to_le_bytes());
                                                let _ = out_file.write_all(&meta_json);
                                                let _ = out_file.write_all(&comp_size.to_le_bytes());
                                                let _ = out_file.write_all(&final_payload);
                                                self.status_text = format!("🔥 SUCCESS! File hidden successfully in: {}", self.output_path);
                                            }
                                            Err(e) => self.status_text = format!("❌ File Create Error: {}", e),
                                        }
