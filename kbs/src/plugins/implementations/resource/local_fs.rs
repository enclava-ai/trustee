// Copyright (c) 2026 by Enclava.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

use super::{ResourceDesc, StorageBackend};

#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
pub struct LocalFsConfig {
    pub dir_path: String,
}

pub struct LocalFs {
    dir_path: PathBuf,
}

impl LocalFs {
    pub fn new(config: LocalFsConfig) -> Self {
        Self {
            dir_path: PathBuf::from(config.dir_path),
        }
    }

    fn resource_path(&self, resource_desc: &ResourceDesc) -> PathBuf {
        Path::new(&self.dir_path)
            .join(&resource_desc.repository_name)
            .join(&resource_desc.resource_type)
            .join(&resource_desc.resource_tag)
    }
}

#[async_trait::async_trait]
impl StorageBackend for LocalFs {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let resource_path = self.resource_path(&resource_desc);

        match tokio::fs::read(&resource_path).await {
            Ok(data) => Ok(data),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                bail!("resource not found: {}", resource_desc)
            }
            Err(err) => Err(err)
                .with_context(|| format!("failed to read resource {}", resource_path.display())),
        }
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let resource_path = self.resource_path(&resource_desc);

        if let Some(parent) = resource_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create resource directory {}", parent.display())
            })?;
        }

        tokio::fs::write(&resource_path, data)
            .await
            .with_context(|| format!("failed to write resource {}", resource_path.display()))?;

        Ok(())
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        let resource_path = self.resource_path(&resource_desc);

        match tokio::fs::remove_file(&resource_path).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err)
                .with_context(|| format!("failed to delete resource {}", resource_path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{LocalFs, LocalFsConfig};
    use crate::plugins::resource::{ResourceDesc, StorageBackend};

    const TEST_DATA: &[u8] = b"testdata";

    #[tokio::test]
    async fn write_and_read_resource() {
        let dir = tempdir().unwrap();
        let storage = LocalFs::new(LocalFsConfig {
            dir_path: dir.path().to_string_lossy().to_string(),
        });
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test-owner".into(),
            resource_tag: "seed-encrypted".into(),
        };

        storage
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");
        let data = storage
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");

        assert_eq!(&data[..], TEST_DATA);
    }

    #[tokio::test]
    async fn read_missing_resource_returns_not_found() {
        let dir = tempdir().unwrap();
        let storage = LocalFs::new(LocalFsConfig {
            dir_path: dir.path().to_string_lossy().to_string(),
        });
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test-owner".into(),
            resource_tag: "missing".into(),
        };

        let err = storage
            .read_secret_resource(resource_desc)
            .await
            .expect_err("missing resource should fail");

        assert!(err.to_string().contains("resource not found:"));
    }

    #[tokio::test]
    async fn delete_missing_resource_is_idempotent() {
        let dir = tempdir().unwrap();
        let storage = LocalFs::new(LocalFsConfig {
            dir_path: dir.path().to_string_lossy().to_string(),
        });
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test-owner".into(),
            resource_tag: "missing".into(),
        };

        storage
            .delete_secret_resource(resource_desc)
            .await
            .expect("delete of missing resource should be a no-op");
    }
}
