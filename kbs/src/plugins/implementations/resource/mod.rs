// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod kv_storage;
pub mod local_fs;

#[cfg(feature = "aliyun")]
pub mod aliyun_kms;

#[cfg(feature = "vault")]
pub mod vault_kv;

use std::collections::HashMap;

use actix_web::http::Method;
use anyhow::{bail, Result};

pub mod backend;
pub use backend::*;

use super::super::plugin_manager::ClientPlugin;

pub(crate) const WORKLOAD_RESOURCE_CONDITION_QUERY: &str = "__kbs_workload_resource_condition";
pub(crate) const WORKLOAD_RESOURCE_CONDITION_CREATE: &str = "create-if-absent";
pub(crate) const WORKLOAD_RESOURCE_CONDITION_REPLACE: &str = "replace-if-present";
pub(crate) const WORKLOAD_RESOURCE_CONDITION_DELETE: &str = "delete-if-present";

#[async_trait::async_trait]
impl ClientPlugin for ResourceStorage {
    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>> {
        let resource_desc = path.join("/");
        match method.as_str() {
            "POST" => {
                let resource_description = ResourceDesc::try_from(&resource_desc[..])?;
                match query
                    .get(WORKLOAD_RESOURCE_CONDITION_QUERY)
                    .map(String::as_str)
                {
                    Some(WORKLOAD_RESOURCE_CONDITION_CREATE) => {
                        if !self
                            .create_secret_resource(resource_description, body)
                            .await?
                        {
                            bail!("resource precondition failed: resource already exists");
                        }
                    }
                    Some(WORKLOAD_RESOURCE_CONDITION_REPLACE) => {
                        if !self
                            .replace_secret_resource(resource_description, body)
                            .await?
                        {
                            bail!("resource precondition failed: resource does not exist");
                        }
                    }
                    Some(other) => bail!("unsupported resource condition: {other}"),
                    None => self.set_secret_resource(resource_description, body).await?,
                }
                Ok(vec![])
            }
            "GET" => {
                let resource_description = ResourceDesc::try_from(&resource_desc[..])?;
                let resource = self.get_secret_resource(resource_description).await?;

                Ok(resource)
            }
            "DELETE" => {
                let resource_description = ResourceDesc::try_from(&resource_desc[..])?;
                match query
                    .get(WORKLOAD_RESOURCE_CONDITION_QUERY)
                    .map(String::as_str)
                {
                    Some(WORKLOAD_RESOURCE_CONDITION_DELETE) => {
                        if !self
                            .delete_existing_secret_resource(resource_description)
                            .await?
                        {
                            bail!("resource precondition failed: resource does not exist");
                        }
                    }
                    Some(other) => bail!("unsupported resource condition: {other}"),
                    None => self.delete_secret_resource(resource_description).await?,
                }
                Ok(vec![])
            }
            _ => bail!("Illegal HTTP method. Only supports `GET`, `POST` and `DELETE`"),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "POST" || method.as_str() == "DELETE" {
            return Ok(true);
        }

        Ok(false)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "GET" {
            return Ok(true);
        }

        Ok(false)
    }
}
