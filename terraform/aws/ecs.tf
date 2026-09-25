resource "aws_cloudwatch_log_group" "edge" {
  name              = "/inwom/${var.name_prefix}"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "edge" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  local_policy = {
    tenant_id        = var.inwom_tenant_id
    environment_id   = var.inwom_environment_id
    max_privacy_mode = var.max_privacy_mode
    allowed_sources = concat(
      (var.cloudtrail_bucket != "" || local.mirror) ? ["CLOUDTRAIL"] : [],
      var.waf_bucket != "" ? ["WAF"] : [],
      var.alb_bucket != "" ? ["ALB"] : [],
      var.vpc_flow_bucket != "" ? ["VPC_FLOW"] : [],
      var.guardduty_detector_id != "" ? ["GUARDDUTY"] : [],
      length(var.cloudwatch_log_group_names) > 0 ? ["CLOUDWATCH"] : [],
      var.enable_iam_metadata ? ["IAM_METADATA"] : [],
      var.enable_compute_metadata ? ["COMPUTE_METADATA"] : [],
    )
    forensic_allowed_fields    = var.forensic_allowed_fields
    ingest_endpoint            = var.ingest_endpoint
    allowed_egress_hosts       = var.allowed_egress_hosts
    config_signing_public_keys = var.config_signing_public_keys
    source_locations = {
      cloudtrail_bucket     = var.cloudtrail_bucket == "" ? null : var.cloudtrail_bucket
      cloudtrail_prefixes   = var.cloudtrail_prefixes
      waf_bucket            = var.waf_bucket == "" ? null : var.waf_bucket
      waf_prefixes          = var.waf_prefixes
      alb_bucket            = var.alb_bucket == "" ? null : var.alb_bucket
      alb_prefixes          = var.alb_prefixes
      vpc_flow_bucket       = var.vpc_flow_bucket == "" ? null : var.vpc_flow_bucket
      vpc_flow_prefixes     = var.vpc_flow_prefixes
      guardduty_detector_id = var.guardduty_detector_id == "" ? null : var.guardduty_detector_id
      cloudwatch_log_groups = var.cloudwatch_log_group_names
    }
    ca_bundle_pem         = var.ca_bundle_pem == "" ? null : var.ca_bundle_pem
    pseudonym_key_version = var.pseudonym_key_version
    kms_mac_key_id        = aws_kms_key.pseudonym.arn
    kms_signing_key_id    = aws_kms_key.identity.arn
    spool_dir             = "/spool"
    durable_queue_url     = var.enable_durable_queue ? aws_sqs_queue.transport[0].url : null
    protected_resources   = var.protected_resources
    spool_max_bytes       = min(8589934592, floor(var.spool_size_gib * 1024 * 1024 * 1024 / 2)) # <= half the ephemeral disk, <= the Edge's 8 GiB validation cap
  }
}

resource "aws_ecs_task_definition" "edge" {
  family                   = var.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  ephemeral_storage {
    size_in_gib = var.spool_size_gib
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  # Ephemeral, task-scoped volumes: nothing persists, nothing is shared.
  volume {
    name = "spool"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([
    {
      # Fargate mounts plain (non-EFS) ephemeral volumes root:root 0755, regardless of what the
      # image bakes in at that path — so the non-root "edge" container below cannot write /spool
      # or /tmp until something chowns them first. This one-shot, essential=false container does
      # that and exits; "edge" waits for it (dependsOn SUCCESS) before starting. Found by a real
      # Fargate deployment: without it, health.beat()'s touch() fails silently (OSError swallowed
      # by design), the container health check never passes, and ECS kills the task every ~5min.
      name       = "init-permissions"
      image      = "${var.image_repository}@${var.image_digest}"
      essential  = false
      user       = "0:0"
      entryPoint = ["sh", "-c"]
      command    = ["chown -R 10001:10001 /tmp /spool"]

      mountPoints = [
        { sourceVolume = "spool", containerPath = "/spool", readOnly = false },
        { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.edge.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "init"
        }
      }
    },
    {
      name      = "edge"
      image     = "${var.image_repository}@${var.image_digest}"
      essential = true
      dependsOn = [{ containerName = "init-permissions", condition = "SUCCESS" }]

      # No portMappings: the container listens on nothing.
      user                   = "10001:10001"
      readonlyRootFilesystem = true
      privileged             = false

      linuxParameters = {
        initProcessEnabled = true
        capabilities       = { drop = ["ALL"] }
      }

      mountPoints = [
        { sourceVolume = "spool", containerPath = "/spool", readOnly = false },
        { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
      ]

      environment = [
        { name = "INWOM_EDGE_LOCAL_POLICY", value = jsonencode(local.local_policy) },
        { name = "PYTHONDONTWRITEBYTECODE", value = "1" },
      ]

      secrets = [
        { name = "INWOM_BOOTSTRAP_TOKEN", valueFrom = aws_secretsmanager_secret.bootstrap.arn },
      ]

      healthCheck = {
        command     = ["CMD", "python", "-m", "inwom_edge.health"]
        interval    = 60
        timeout     = 10
        retries     = 3
        startPeriod = 120
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.edge.name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "edge"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "edge" {
  name            = var.name_prefix
  cluster         = aws_ecs_cluster.edge.id
  task_definition = aws_ecs_task_definition.edge.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # No shell into the task, ever. (Also enforced: the task role has no ssmmessages permissions.)
  enable_execute_command = false

  # Single instance: stop the old task before starting the new one so two Edges never read the same sources.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.edge.id]
    assign_public_ip = false
  }
}
