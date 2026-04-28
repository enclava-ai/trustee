// Copyright (c) 2026 by Enclava.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use super::{ResourceDesc, StorageBackend};

#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
pub struct LocalFsConfig {
    pub dir_path: String,
}

pub struct LocalFs {
    dir_path: PathBuf,
    lock: RwLock<()>,
}

impl LocalFs {
    pub fn new(config: LocalFsConfig) -> Self {
        Self {
            dir_path: PathBuf::from(config.dir_path),
            lock: RwLock::new(()),
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
        let _ = self.lock.read().await;
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
        let _ = self.lock.write().await;
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

    async fn write_secret_resource_if_absent(
        &self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<bool> {
        let _ = self.lock.write().await;
        let resource_path = self.resource_path(&resource_desc);

        if let Some(parent) = resource_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create resource directory {}", parent.display())
            })?;
        }

        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&resource_path)
            .await;
        let mut file = match file {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => return Ok(false),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create resource {}", resource_path.display())
                })
            }
        };

        file.write_all(data)
            .await
            .with_context(|| format!("failed to write resource {}", resource_path.display()))?;

        Ok(true)
    }

    async fn write_secret_resource_if_present(
        &self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<bool> {
        let _ = self.lock.write().await;
        let resource_path = self.resource_path(&resource_desc);
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&resource_path)
            .await;
        let mut file = match file {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to open resource {}", resource_path.display())
                })
            }
        };

        file.write_all(data)
            .await
            .with_context(|| format!("failed to write resource {}", resource_path.display()))?;

        Ok(true)
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        let _ = self.lock.write().await;
        let resource_path = self.resource_path(&resource_desc);

        match tokio::fs::remove_file(&resource_path).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err)
                .with_context(|| format!("failed to delete resource {}", resource_path.display())),
        }
    }

    async fn delete_secret_resource_if_present(&self, resource_desc: ResourceDesc) -> Result<bool> {
        let _ = self.lock.write().await;
        let resource_path = self.resource_path(&resource_desc);

        match tokio::fs::remove_file(&resource_path).await {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
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

    #[tokio::test]
    async fn create_if_absent_is_first_write_wins() {
        let dir = tempdir().unwrap();
        let storage = LocalFs::new(LocalFsConfig {
            dir_path: dir.path().to_string_lossy().to_string(),
        });
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test-owner".into(),
            resource_tag: "seed-encrypted".into(),
        };

        assert!(storage
            .write_secret_resource_if_absent(resource_desc.clone(), b"first")
            .await
            .expect("first create failed"));
        assert!(!storage
            .write_secret_resource_if_absent(resource_desc.clone(), b"second")
            .await
            .expect("second create failed"));

        let data = storage
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");
        assert_eq!(&data[..], b"first");
    }

    #[tokio::test]
    async fn replace_if_present_requires_existing_resource() {
        let dir = tempdir().unwrap();
        let storage = LocalFs::new(LocalFsConfig {
            dir_path: dir.path().to_string_lossy().to_string(),
        });
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test-owner".into(),
            resource_tag: "replace-existing".into(),
        };

        assert!(!storage
            .write_secret_resource_if_present(resource_desc.clone(), b"missing")
            .await
            .expect("missing replace failed"));

        storage
            .write_secret_resource(resource_desc.clone(), b"old")
            .await
            .expect("write secret resource failed");
        assert!(storage
            .write_secret_resource_if_present(resource_desc.clone(), b"new")
            .await
            .expect("existing replace failed"));

        let data = storage
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");
        assert_eq!(&data[..], b"new");
    }

    #[tokio::test]
    async fn delete_if_present_requires_existing_resource() {
        let dir = tempdir().unwrap();
        let storage = LocalFs::new(LocalFsConfig {
            dir_path: dir.path().to_string_lossy().to_string(),
        });
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test-owner".into(),
            resource_tag: "delete-existing".into(),
        };

        assert!(!storage
            .delete_secret_resource_if_present(resource_desc.clone())
            .await
            .expect("missing delete failed"));

        storage
            .write_secret_resource(resource_desc.clone(), b"old")
            .await
            .expect("write secret resource failed");
        assert!(storage
            .delete_secret_resource_if_present(resource_desc.clone())
            .await
            .expect("existing delete failed"));

        assert!(storage.read_secret_resource(resource_desc).await.is_err());
    }
}
