//! Test fixture: an application that crashes immediately with a genuine fatal
//! exception (stack-buffer-overrun fail-fast, exit code 0xC0000409).
fn main() {
    std::process::abort();
}
