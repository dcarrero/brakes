//! Per-language packs as data (SPEC-stack-packs.md). A pack is a constant: the
//! files that suggest it, the commands it proposes, the lockfile flag, the seeds
//! it writes and the CI setup steps it contributes, every `uses:` and `FROM`
//! pinned from one shared table. Nothing here runs a command or reads the
//! network. The recorded answers say which packs apply and where; consumers ask
//! through `required_packs(cx)`; `detect` proposes answers from files and writes nothing.
//! `render` seeds each app's toolchain pin file and protects the manifest it
//! reads, and each container app's Dockerfile and `.dockerignore`.
pub mod answers;
pub mod audit;
pub mod container;
pub mod detect;
pub mod pack;
pub mod packs;
pub mod pins;
pub mod seeds;
pub mod versions;

pub use answers::{
    AppAnswers, AppId, BaseImageFamily, StackPacksAnswers, active_packs, packs, required_packs,
};
pub use pack::*;
pub use pins::*;

use crate::{
    Result,
    engine::{Context, Module, Rendered, Schema},
};

/// Module id as the lock and the answers file record it.
pub const STACK_PACKS: &str = "stack-packs";
pub const STACK_PACKS_VERSION: &str = "1.0.0";

pub struct StackPacks;

impl Module for StackPacks {
    fn id(&self) -> &'static str {
        STACK_PACKS
    }
    fn version(&self) -> &'static str {
        STACK_PACKS_VERSION
    }
    fn questions(&self) -> Schema {
        answers::schema()
    }
    /// Per app, in app id order: the toolchain seed and the never-touch
    /// manifest (`seeds`), then the Dockerfile and `.dockerignore` of a
    /// container app (`container`). It loads the answers, so every rule refuses
    /// at `configure` and `install`, and a family whose pins are unfilled
    /// (`dhi`) refuses naming the image key.
    fn render(&self, cx: &Context<'_>) -> Result<Vec<Rendered>> {
        let answers = StackPacksAnswers::load(cx)?;
        let pins = PinTable::embedded()?;
        let generated: Vec<String> = cx.profile.value["generated_paths"]
            .as_array()
            .map(|paths| {
                paths
                    .iter()
                    .filter_map(|path| Some(path.as_str()?.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let mut rendered = Vec::new();
        for app in answers.apps.values() {
            rendered.extend(seeds::toolchain(
                cx.root,
                &app.app,
                app.toolchain_version.as_deref(),
                &pins,
            )?);
            rendered.extend(container::seeds(
                app,
                answers.base_image_family,
                &pins,
                &generated,
            )?);
        }
        Ok(rendered)
    }
}
