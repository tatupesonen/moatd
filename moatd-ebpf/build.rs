fn main() {
    let bpf_linker = which::which("bpf-linker").expect("bpf-linker missing in PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.display());
}
