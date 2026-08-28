# 🚀 LinuxForge

An ultra-fast, standalone Rust executable compiled with `musl-libc` to run seamlessly across **all Linux distributions** without any external dependencies.

## ✨ Features
* 📦 **Statically Linked:** Zero external library requirements (No glibc version errors).
* 🐧 **Universal:** Works on Ubuntu, Fedora, Arch, Alpine, and more.
* ⚡ **Performance:** Built using Rust for blazing-fast execution.

## 🛠️ How to Download & Run

1. Go to the **Actions** tab of this repository.
2. Click on the latest successful build workflow.
3. Scroll down to **Artifacts** and download the `linux-executable`.
4. Open your Linux terminal and navigate to the downloaded folder.
5. Give execution permission and run it:
   ```bash
   chmod +x ./your_program_name
   ./your_program_name
   ```

## 🏗️ Local Compilation (Optional)
If you want to compile this on your machine locally:
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```
