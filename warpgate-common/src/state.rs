use std::path::PathBuf;

use anyhow::Context;

#[derive(Clone)]
pub struct GlobalParams {
    config_path: PathBuf,
    should_secure_files: bool,
    paths_relative_to: PathBuf,
}

impl GlobalParams {
    pub fn new(config_path: PathBuf, should_secure_files: bool) -> anyhow::Result<Self> {
        Ok(Self {
            paths_relative_to: config_path
                .parent()
                .context("Failed to determine config parent directory")?
                .to_path_buf(),
            config_path,
            should_secure_files,
        })
    }

    pub fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    pub fn paths_relative_to(&self) -> &PathBuf {
        &self.paths_relative_to
    }

    pub fn should_secure_files(&self) -> bool {
        self.should_secure_files
    }
}
