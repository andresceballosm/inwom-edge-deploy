# CUSTOMER_TELEMETRY_MIRROR: a destination that belongs to YOU, exists only for Inwom Edge, and receives only the telemetry
# selected here. A dedicated trail (your own trail is untouched) writes management events to a bucket encrypted with a key
# owned by you and usable only through S3 by the Edge. The Edge never receives decrypt rights on any of your other keys.

locals {
  mirror     = var.cloudtrail_access_mode == "CUSTOMER_TELEMETRY_MIRROR"
  mirror_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}-mirror"

  # S3 *object* reads/writes (GetObject, PutObject, ...) are CloudTrail DATA events — management
  # events alone (the only thing this trail logged before) never capture them, at any ReadWriteType.
  # Found via real-AWS validation: an actual read of a RESTRICTED-classified S3 object left no
  # CloudTrail record anywhere, on any of your data's real ARN, only via a real breach test. Cover
  # exactly what you told us to watch, derived from `protected_resources` (an S3 ARN there means
  # you already classified that bucket/object; nothing broader is turned on automatically).
  mirror_protected_s3_bucket_arns = distinct([
    for id in [for r in var.protected_resources : r.identifier if can(regex("^arn:[^:]+:s3:::", r.identifier))] : split("/", id)[0]
  ])
}

data "aws_iam_policy_document" "mirror_key" {
  count = local.mirror ? 1 : 0

  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncryptsMirrorLogs"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.mirror_arn]
    }
  }
}

resource "aws_kms_key" "mirror" {
  count                   = local.mirror ? 1 : 0
  description             = "Inwom Edge telemetry mirror (customer-owned)"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.mirror_key[0].json
}

resource "aws_kms_alias" "mirror" {
  count         = local.mirror ? 1 : 0
  name          = "alias/${var.name_prefix}-mirror"
  target_key_id = aws_kms_key.mirror[0].key_id
}

resource "aws_s3_bucket" "mirror" {
  count  = local.mirror ? 1 : 0
  bucket = "${var.name_prefix}-mirror-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "mirror" {
  count                   = local.mirror ? 1 : 0
  bucket                  = aws_s3_bucket.mirror[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mirror" {
  count  = local.mirror ? 1 : 0
  bucket = aws_s3_bucket.mirror[0].id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.mirror[0].arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "mirror" {
  count  = local.mirror ? 1 : 0
  bucket = aws_s3_bucket.mirror[0].id
  rule {
    id     = "expire-telemetry"
    status = "Enabled"
    filter {}
    expiration {
      days = var.mirror_retention_days
    }
  }
}

data "aws_iam_policy_document" "mirror_bucket" {
  count = local.mirror ? 1 : 0

  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.mirror[0].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.mirror_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.mirror[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.mirror_arn]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.mirror[0].arn,
      "${aws_s3_bucket.mirror[0].arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "mirror" {
  count  = local.mirror ? 1 : 0
  bucket = aws_s3_bucket.mirror[0].id
  policy = data.aws_iam_policy_document.mirror_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.mirror]
}

resource "aws_cloudtrail" "mirror" {
  count          = local.mirror ? 1 : 0
  name           = "${var.name_prefix}-mirror"
  s3_bucket_name = aws_s3_bucket.mirror[0].id
  kms_key_id     = aws_kms_key.mirror[0].arn
  # Multi-region, not just include_global_service_events: a single-region trail whose home region
  # is not us-east-1 never receives global-service (IAM, etc.) events regardless of that flag —
  # found the same way, via real-AWS validation.
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = var.mirror_read_write_type
    include_management_events = true

    dynamic "data_resource" {
      for_each = length(local.mirror_protected_s3_bucket_arns) > 0 ? [1] : []
      content {
        type   = "AWS::S3::Object"
        values = [for arn in local.mirror_protected_s3_bucket_arns : "${arn}/"]
      }
    }
  }

  depends_on = [aws_s3_bucket_policy.mirror]
}
