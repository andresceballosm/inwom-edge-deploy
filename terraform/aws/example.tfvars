# Copy to terraform.tfvars and fill in from the Inwom dashboard ("Add AWS environment").
inwom_tenant_id      = "ten_replaceme0001"
inwom_environment_id = "env_replaceme0001"
# bootstrap_token is sensitive: pass it via  TF_VAR_bootstrap_token=...  rather than a file.
config_signing_public_keys = ["REPLACE_WITH_KEY_FROM_DASHBOARD"]
image_digest               = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

vpc_id     = "vpc-0123456789abcdef0"
subnet_ids = ["subnet-0123456789abcdef0", "subnet-0fedcba9876543210"]

cloudtrail_bucket   = "my-org-cloudtrail-logs"
cloudtrail_prefixes = ["AWSLogs/123456789012/CloudTrail/us-east-1/{yyyy}/{mm}/{dd}/"]

max_privacy_mode = "STRICT"
