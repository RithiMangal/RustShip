use std::env;
use std::process::Command;

fn main() {
    println!("========================================");
    println!("   🔥 WELCOME TO LINUX FORGE TOOL 🔥   ");
    println!("========================================");

    // 1. தற்போதைய பயனர் விவரம்
    if let Ok(user) = env::var("USER") {
        println!("👤 Current User : {}", user);
    }

    // 2. லினக்ஸ் கர்னல் பதிப்பு (Kernel Version)
    if let Ok(output) = Command::new("uname").arg("-sr").output() {
        let kernel = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("🐧 Kernel Info  : {}", kernel);
    }

    // 3. சிஸ்டம் இயக்க நேரம் (Uptime)
    if let Ok(output) = Command::new("uptime").arg("-p").output() {
        let uptime = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("⏰ Uptime       : {}", uptime);
    }

    println!("========================================");
    println!("🚀 Run successfully on a standalone binary!");
    println!("========================================");
}
