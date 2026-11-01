//! Shared by the test files that build module lists with `setup-core` in them
//! (product-boundary T7b, #1057): with the feature they get the real module;
//! without it a stand-in with the same id that renders nothing, so every other
//! module's tests run in both builds. Not every file uses every item.
#![allow(dead_code, unused_imports)]

#[cfg(feature = "setup-core")]
pub use brakes::modules::SetupCore;

/// `setup-core` is not compiled in: a module with its id and no content.
#[cfg(not(feature = "setup-core"))]
pub struct SetupCore;

#[cfg(not(feature = "setup-core"))]
impl brakes::engine::Module for SetupCore {
    fn id(&self) -> &'static str {
        "setup-core"
    }
    fn version(&self) -> &'static str {
        brakes::modules::core_version()
    }
    fn render(
        &self,
        _: &brakes::engine::Context<'_>,
    ) -> brakes::Result<Vec<brakes::engine::Rendered>> {
        Ok(Vec::new())
    }
}

/// `setup-core`'s guides, by file name; none without the feature.
pub fn guides() -> &'static [(&'static str, &'static str)] {
    #[cfg(feature = "setup-core")]
    return brakes::DOCUMENTS;
    #[cfg(not(feature = "setup-core"))]
    return &[];
}

/// `ids` behind `setup-core` when it is compiled in, as `modules::all()`
/// lists them: the registry's order without the feature drops only it.
pub fn with_core(ids: &[&'static str]) -> Vec<&'static str> {
    let core: &[&'static str] = if cfg!(feature = "setup-core") {
        &["setup-core"]
    } else {
        &[]
    };
    core.iter().chain(ids).copied().collect()
}
