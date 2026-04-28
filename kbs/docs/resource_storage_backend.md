# Resource Storage Backend 

KBS stores confidential resources through a `StorageBackend` abstraction specified
by a Rust trait. The `StorageBackend` interface can be implemented for different
storage backends like e.g. databases or local file systems.

The [KBS config file](./config.md)
defines which resource backend KBS will use. The default is the local
file system (`LocalFs`).

### Local File System Backend

With the local file system backend default implementation, each resource
file maps to a KBS resource URL. The file path to URL conversion scheme is
defined below:

| Resource File Path  | Resource URL |
| ------------------- | -------------- |
| `file://<$(KBS_REPOSITORY_DIR)>/<repository_name>/<type>/<tag>`  |  `https://<kbs_address>/kbs/v0/resource/<repository_name>/<type>/<tag>`  |

The KBS root file system resource path is specified in the KBS config file
as well, and the default value is `/opt/confidential-containers/kbs/repository`.

### Workload Resource Conditional Writes

The workload-owned resource endpoint (`PUT`/`DELETE /kbs/v0/workload-resource/...`)
requires HTTP preconditions:

| Operation | Required header | Backend behavior |
| --------- | --------------- | ---------------- |
| First write | `If-None-Match: *` | Create only when the resource is absent. |
| Rekey/replace | `If-Match: *` | Replace only when the resource is present. |
| Delete | `If-Match: *` | Delete only when the resource is present. |

Requests without one of these headers fail closed with `412 Precondition Failed`.
For the key-value backed resource repository, first write uses the storage
backend's insert-if-absent path (`SetParameters { overwrite: false }`), replace
uses `update_if_present`, and delete uses `delete_if_present`. These operations
are a single storage operation for PostgreSQL and are protected by backend locks
for the in-process backends. The resource local-file backend uses `create_new`
for first-write atomicity and serializes conditional replace/delete in process.

Remaining gap: resource storage does not yet expose per-resource versions or
ETags. The workload-resource HTTP adapter only accepts wildcard preconditions
(`If-None-Match: *` / `If-Match: *`) and forwards an enum condition to the
resource plugin; `KeyValueStorage` stores only key/value bytes and does not
return version metadata from reads or writes. Because there is no end-to-end
version value to compare, `If-Match: *` is an existence precondition, not a full
compare-and-set against a specific version. Backends that do not override the
conditional methods fail closed for workload-resource conditional operations.

### Aliyun KMS

[Alibaba Cloud KMS](https://www.alibabacloud.com/en/product/kms?_p_lc=1)(a.k.a Aliyun KMS)
can also work as the KBS resource storage backend.
In this mode, resources will be stored with [generic secrets](https://www.alibabacloud.com/help/en/kms/user-guide/manage-and-use-generic-secrets?spm=a2c63.p38356.0.0.dc4d24f7s0ZuW7) in a [KMS instance](https://www.alibabacloud.com/help/en/kms/user-guide/kms-overview?spm=a2c63.p38356.0.0.4aacf9e6V7IQGW).
One KBS can be configured with a specified KMS instance in `repository_config` field of KBS launch config. For config, see the [document](./config.md#repository-configuration).
These materials can be found in KMS instance's [AAP](https://www.alibabacloud.com/help/en/kms/user-guide/manage-aaps?spm=a3c0i.23458820.2359477120.1.4fd96e9bmEFST4).
When being accessed, a resource URI of `kbs:///repo/type/tag` will be translated into the generic secret with name `tag`. Hinting that `repo/type` field will be ignored.

### Hashicorp Vault Backend

[Vault KV secrets engine backend](./vault_kv.md)
