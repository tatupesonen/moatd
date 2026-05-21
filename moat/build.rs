use anyhow::{anyhow, Context as _, Result};
use aya_build::Toolchain;
use cargo_metadata::{Metadata, MetadataCommand, Package};

fn main() -> Result<()> {
    let Metadata { packages, .. } = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("cargo metadata")?;

    let ebpf_pkg = packages
        .into_iter()
        .find(|Package { name, .. }| name.as_str() == "moat-ebpf")
        .ok_or_else(|| anyhow!("moat-ebpf package not found in workspace"))?;

    let Package {
        name,
        manifest_path,
        ..
    } = ebpf_pkg;
    let root_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for {manifest_path}"))?
        .as_str();

    aya_build::build_ebpf(
        [aya_build::Package {
            name: name.as_str(),
            root_dir,
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )
}
