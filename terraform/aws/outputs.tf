output "security_group_id" {
  description = "Edge security group (no ingress rules)."
  value       = aws_security_group.edge.id
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "identity_key_arn" {
  description = "KMS key holding the installation's identity (non-exportable). Its fingerprint appears in the Inwom dashboard."
  value       = aws_kms_key.identity.arn
}

output "pseudonym_key_arn" {
  description = "KMS key from which pseudonym and spool keys are derived. Disable it to stop all pseudonymization immediately."
  value       = aws_kms_key.pseudonym.arn
}

output "log_group" {
  value = aws_cloudwatch_log_group.edge.name
}

output "deployed_image" {
  description = "The exact immutable image reference that was deployed."
  value       = "${var.image_repository}@${var.image_digest}"
}

output "queue_url" {
  description = "The Edge-owned transport queue (encrypted; the runtime role may act only on this queue)."
  value       = var.enable_durable_queue ? aws_sqs_queue.transport[0].url : null
}
