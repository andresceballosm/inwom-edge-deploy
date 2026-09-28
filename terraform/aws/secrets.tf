# The ONLY secret in this deployment: a single-use, 1-hour registration token. After the Edge
# registers, the token is spent; the long-lived identity is a non-exportable KMS key, not a secret.

resource "aws_secretsmanager_secret" "bootstrap" {
  name                    = "${var.name_prefix}/bootstrap-token"
  description             = "Single-use Inwom Edge registration token (spent after first registration)."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "bootstrap" {
  secret_id     = aws_secretsmanager_secret.bootstrap.id
  secret_string = var.bootstrap_token

  # The bootstrap token is intentionally single-use. Create it for first registration, then leave
  # the stored (spent) value alone: the long-lived Edge identity is the non-exportable KMS key.
  lifecycle {
    ignore_changes = [secret_string]
  }
}
