use std::path::Path;

fn main() {
    // Make Slint's bundled styles available and compile the UI.
    slint_build::compile_with_config("ui/main.slint", slint_build::CompilerConfiguration::new().with_style("fluent".into()))
        .expect("Slint compilation failed");

    println!("cargo:rerun-if-changed=ui");
    println!("cargo:rerun-if-changed=../../icon.ico");
    println!("cargo:rerun-if-env-changed=RELEASEVERITY_REQUIRE_ICON");
    println!("cargo:rerun-if-env-changed=RELEASEVERITY_ICON");

    // Windows: embed the product icon and version metadata into the EXE.
    // `icon.ico` (repo root, provided by the project owner) is used unmodified.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // `RELEASEVERITY_ICON` lets the build script point at an icon elsewhere; the default is the repo's icon.ico.
        let icon = std::env::var_os("RELEASEVERITY_ICON")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../icon.ico"));
        let require = std::env::var("RELEASEVERITY_REQUIRE_ICON").map(|v| v == "1").unwrap_or(false);
        if !icon.is_file() {
            let msg = format!(
                "icon.ico was not found at {}. Place the product icon at the repository root (it is embedded unmodified into ReleaseVerity.exe, the installer and the shortcuts).",
                icon.display()
            );
            if require {
                panic!("{msg}");
            }
            println!("cargo:warning={msg} (development build continues without it)");
            return;
        }
        let version = env!("CARGO_PKG_VERSION");
        let mut res = winresource::WindowsResource::new();
        res.set_icon(icon.to_str().expect("utf-8 path"));
        res.set("ProductName", "ReleaseVerity");
        res.set("FileDescription", "ReleaseVerity - Release Verification & Software Quality Platform");
        res.set("CompanyName", "ReleaseVerity contributors");
        res.set("LegalCopyright", "Apache-2.0");
        res.set("ProductVersion", version);
        res.set("FileVersion", version);
        if let Err(e) = res.compile() {
            if require {
                panic!("embedding icon/version resources failed: {e}");
            }
            println!("cargo:warning=embedding icon/version resources failed: {e}");
        }
    }
}
