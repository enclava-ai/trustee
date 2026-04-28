// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{ResourceDesc, StorageBackend};
use anyhow::{bail, Result};
use key_value_storage::{
    DeleteResult, KeyValueStorage, KeyValueStorageInstance, SetParameters, SetResult, UpdateResult,
};
use std::sync::Arc;

pub struct KvStorage {
    pub storage: Arc<dyn KeyValueStorage>,
}

#[async_trait::async_trait]
impl StorageBackend for KvStorage {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        let Some(resource_byte) = self.storage.get(&ref_resource_path).await? else {
            bail!("resource not found: {}", ref_resource_path);
        };

        Ok(resource_byte)
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        self.storage
            .set(&ref_resource_path, data, SetParameters { overwrite: true })
            .await?;

        Ok(())
    }

    async fn write_secret_resource_if_absent(
        &self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<bool> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        let result = self
            .storage
            .set(&ref_resource_path, data, SetParameters { overwrite: false })
            .await?;

        Ok(matches!(result, SetResult::Inserted))
    }

    async fn write_secret_resource_if_present(
        &self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<bool> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        Ok(matches!(
            self.storage
                .update_if_present(&ref_resource_path, data)
                .await?,
            UpdateResult::Updated
        ))
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        let _ = self.storage.delete(&ref_resource_path).await?;

        Ok(())
    }

    async fn delete_secret_resource_if_present(&self, resource_desc: ResourceDesc) -> Result<bool> {
        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );

        Ok(matches!(
            self.storage.delete_if_present(&ref_resource_path).await?,
            DeleteResult::Deleted(_)
        ))
    }
}

impl KvStorage {
    pub fn new(storage: KeyValueStorageInstance) -> Self {
        Self { storage }
    }
}

#[cfg(test)]
mod tests {
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
    use std::sync::Arc;

    use crate::plugins::resource::{kv_storage::KvStorage, RESOURCE_STORAGE_NAMESPACE};

    use super::super::{ResourceDesc, StorageBackend};

    const TEST_DATA: &[u8] = b"testdata";

    #[tokio::test]
    async fn write_and_read_resource() {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_NAMESPACE)
            .await
            .expect("create key value storage failed");

        let local_fs = KvStorage::new(storage);
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "test".into(),
        };

        local_fs
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");
        let data = local_fs
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");

        assert_eq!(&data[..], TEST_DATA);
    }

    #[tokio::test]
    async fn delete_missing_resource_is_idempotent() {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_NAMESPACE)
            .await
            .expect("create key value storage failed");

        let local_fs = KvStorage::new(storage);
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "missing".into(),
        };

        local_fs
            .delete_secret_resource(resource_desc)
            .await
            .expect("delete of missing resource should be a no-op");
    }

    #[tokio::test]
    async fn create_if_absent_is_first_write_wins() {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_NAMESPACE)
            .await
            .expect("create key value storage failed");

        let local_fs = KvStorage::new(storage);
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "create-once".into(),
        };

        assert!(
            local_fs
                .write_secret_resource_if_absent(resource_desc.clone(), b"first")
                .await
                .expect("first create failed"),
            "first create should insert"
        );
        assert!(
            !local_fs
                .write_secret_resource_if_absent(resource_desc.clone(), b"second")
                .await
                .expect("second create failed"),
            "second create should be rejected"
        );

        let data = local_fs
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");
        assert_eq!(&data[..], b"first");
    }

    #[tokio::test]
    async fn concurrent_create_if_absent_allows_one_writer() {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_NAMESPACE)
            .await
            .expect("create key value storage failed");

        let storage = Arc::new(KvStorage::new(storage));
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "concurrent-create".into(),
        };
        let mut tasks = Vec::new();

        for i in 0..16 {
            let storage = storage.clone();
            let resource_desc = resource_desc.clone();
            tasks.push(tokio::spawn(async move {
                storage
                    .write_secret_resource_if_absent(
                        resource_desc,
                        format!("writer-{i}").as_bytes(),
                    )
                    .await
                    .expect("conditional create failed")
            }));
        }

        let mut inserted = 0;
        for task in tasks {
            if task.await.expect("task panicked") {
                inserted += 1;
            }
        }

        assert_eq!(inserted, 1);
    }

    #[tokio::test]
    async fn replace_if_present_requires_existing_resource() {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_NAMESPACE)
            .await
            .expect("create key value storage failed");

        let local_fs = KvStorage::new(storage);
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "replace-existing".into(),
        };

        assert!(!local_fs
            .write_secret_resource_if_present(resource_desc.clone(), b"missing")
            .await
            .expect("missing replace failed"));

        local_fs
            .write_secret_resource(resource_desc.clone(), b"old")
            .await
            .expect("write secret resource failed");
        assert!(local_fs
            .write_secret_resource_if_present(resource_desc.clone(), b"new")
            .await
            .expect("existing replace failed"));

        let data = local_fs
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");
        assert_eq!(&data[..], b"new");
    }

    #[tokio::test]
    async fn delete_if_present_requires_existing_resource() {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, RESOURCE_STORAGE_NAMESPACE)
            .await
            .expect("create key value storage failed");

        let local_fs = KvStorage::new(storage);
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "delete-existing".into(),
        };

        assert!(!local_fs
            .delete_secret_resource_if_present(resource_desc.clone())
            .await
            .expect("missing delete failed"));

        local_fs
            .write_secret_resource(resource_desc.clone(), b"old")
            .await
            .expect("write secret resource failed");
        assert!(local_fs
            .delete_secret_resource_if_present(resource_desc.clone())
            .await
            .expect("existing delete failed"));

        assert!(local_fs.read_secret_resource(resource_desc).await.is_err());
    }
}
