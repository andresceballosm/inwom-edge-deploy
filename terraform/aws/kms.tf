data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# Both keys live in YOUR account. Neither can be exported. Disabling either key is an immediate,
# customer-controlled kill switch (pseudonyms/spool key can no longer be derived; the Edge cannot authenticate).

data "aws_iam_policy_document" "key_policy" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "pseudonym" {
  description              = "Inwom Edge pseudonymization + spool key derivation (HMAC, non-exportable)"
  key_usage                = "GENERATE_VERIFY_MAC"
  customer_master_key_spec = "HMAC_256"
  deletion_window_in_days  = var.kms_deletion_window_days
  policy                   = data.aws_iam_policy_document.key_policy.json
}

resource "aws_kms_alias" "pseudonym" {
  name          = "alias/${var.name_prefix}-pseudonym"
  target_key_id = aws_kms_key.pseudonym.key_id
}

resource "aws_kms_key" "identity" {
  description              = "Inwom Edge installation identity (ECDSA P-256, non-exportable)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = var.kms_deletion_window_days
  policy                   = data.aws_iam_policy_document.key_policy.json
}

resource "aws_kms_alias" "identity" {
  name          = "alias/${var.name_prefix}-identity"
  target_key_id = aws_kms_key.identity.key_id
}
