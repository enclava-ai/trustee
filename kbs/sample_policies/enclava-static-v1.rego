package policy

import rego.v1

default allow := false

authorization := data.deployment_authorization
attested := data.canonical_attested_workload

allow if {
  data.plugin == "resource"
  data.method == "GET"
  verified_deployment
  requested_resource_path in authorization.authorized_resource_paths
}

allow if {
  data.plugin == "workload-resource"
  data.method == "PUT"
  verified_deployment
  requested_resource_path in authorization.authorized_resource_paths
  data.request.body.operation == "rekey"
  data.request.body.receipt.signature_valid
  data.request.body.receipt.pubkey_hash_matches
  data.request.body.receipt.payload.purpose == "enclava-rekey-v1"
  data.request.body.receipt.payload.resource_path == requested_resource_path
  data.request.body.value_hash_matches
}

allow if {
  data.plugin == "workload-resource"
  data.method == "DELETE"
  verified_deployment
  requested_resource_path in authorization.authorized_resource_paths
  data.request.body.operation == "teardown"
  data.request.body.receipt.signature_valid
  data.request.body.receipt.pubkey_hash_matches
  data.request.body.receipt.payload.purpose == "enclava-teardown-v1"
  data.request.body.receipt.payload.resource_path == requested_resource_path
}

verified_deployment if {
  data.authorization_verified == true
  authorization.schema_version == "enclava-kbs-deployment-authorization-v1"
  authorization.descriptor_core_hash == attested.descriptor_core_hash
  authorization.expected_init_data_hash == attested.init_data_hash
  authorization.namespace == attested.namespace
  authorization.service_account == attested.service_account
  authorization.tenant_instance_identity_hash == attested.identity_hash
  authorization.image_digest == attested.image_digest
  authorization.signer_identity.subject == attested.signer_identity.subject
  authorization.signer_identity.issuer == attested.signer_identity.issuer
}

requested_resource_path := path if {
  resource_path := data["resource-path"]
  is_array(resource_path)
  count(resource_path) == 3
  path := concat("/", resource_path)
}

requested_resource_path := path if {
  resource_path := data["resource-path"]
  is_string(resource_path)
  parts := split(trim(resource_path, "/"), "/")
  count(parts) == 3
  path := concat("/", parts)
}
