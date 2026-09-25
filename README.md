# Inwom Edge — deployment templates

Deployment templates for installing the Inwom Edge collector inside your own cloud account. You do
**not** need access to Inwom's main source repository to use these — the Edge's own source and these
templates are what you're inspecting; the detection engine stays in Inwom Cloud.

**AWS today.** More clouds (Azure, GCP) land here as separate top-level directories as they ship —
nothing here changes shape when they do.

## What you are installing

* One small ECS Fargate task (0.25 vCPU / 512 MiB) with **no inbound rules, no public IP, no SSH, no shell**.
* Two KMS keys in your account (pseudonymization, identity) — you can disable either at any time to stop the Edge.
* A read-only IAM role scoped to only the specific buckets/detectors/log groups you name.
* It sends Inwom **sanitized, pseudonymous** events only. Raw logs never leave your account by default.

## 1. Get your values

From the Inwom dashboard, under your environment: `tenant_id` · `environment_id` · a one-time
`bootstrap_token` (valid 1 hour — use it soon) · Inwom's `config_signing_public_keys`.

## 2. Deploy — Terraform

```hcl
module "inwom_edge" {
  source = "github.com/andresceballosm/inwom-edge-deploy//terraform/aws"

  inwom_tenant_id            = "ten_…"
  inwom_environment_id       = "env_…"
  bootstrap_token            = var.bootstrap_token          # export TF_VAR_bootstrap_token=…
  config_signing_public_keys = ["…from the dashboard…"]
  ingest_endpoint            = "https://ingest.inwom.com"
  allowed_egress_hosts       = ["ingest.inwom.com"]

  vpc_id     = "vpc-…"
  subnet_ids = ["subnet-…"]                                 # PRIVATE subnets routed via your NAT / firewall

  cloudtrail_bucket     = "my-org-cloudtrail"
  cloudtrail_prefixes   = ["AWSLogs/123456789012/CloudTrail/us-east-1/{yyyy}/{mm}/{dd}/"]
  guardduty_detector_id = "…"
  enable_iam_metadata   = true

  max_privacy_mode = "STRICT"                               # the ceiling — Inwom can only narrow it
}
```

`terraform init && terraform apply`. See [`terraform/aws/example.tfvars`](terraform/aws/example.tfvars) for every input.

**Before you deploy (only if you're using your own existing CloudTrail, not an Inwom-managed mirror) —
two things found by real testing, not just by reading the docs:**

1. **S3 object reads are invisible unless your trail logs data events.** CloudTrail's management
   events (the default, and often the only thing a trail logs) never include `GetObject`,
   `PutObject`, or `ListObjects`, at any `ReadWriteType`. If you want Inwom to see contact with a
   bucket you classify as sensitive, your trail needs a
   [data event selector](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
   covering that bucket.
2. **A single-region trail whose home region is not `us-east-1` never receives IAM/global-service
   events**, even with `include_global_service_events = true` — and if it *is* multi-region, those
   events still land in a separate `.../CloudTrail/us-east-1/...` S3 prefix, distinct from your
   trail's home region. Make sure `cloudtrail_prefixes` includes that `us-east-1` prefix too if you
   want IAM activity visible.

## 3. Deploy — CloudFormation

Create a stack from [`cloudformation/aws/inwom-edge.yaml`](cloudformation/aws/inwom-edge.yaml) and
fill the same parameters (`BootstrapToken` is `NoEcho`). Limits vs Terraform: one S3 prefix per
source, `STRICT`/`STANDARD` privacy modes only, no optional VPC endpoints.

## 4. Confirm

The dashboard shows **Connected** within a few minutes. In your account you can see the task in ECS,
its logs (`/inwom/<name>` — event codes and counters only, never event content), and every call it
makes in **CloudTrail** (role `<name>-task`).

## Privacy modes (your choice; the ceiling lives in your IaC)

| Mode | Leaves your account |
|---|---|
| **STRICT** (default) | event category, timestamps, pseudonymous actors/resources/sessions, behavioural flags, aggregate counters |
| **STANDARD** | + sanitized action names, service, region, coarse network class, normalized error class |
| **FORENSIC** (off by default; needs `max_privacy_mode = "FORENSIC"` *and* `forensic_allowed_fields`) | + only the evidence fields you enable, per source. Credentials, card numbers and bodies are still blocked |

## Egress

Allow `ingest.inwom.com:443` (TLS 1.3) and the AWS endpoints you use.

## Operations

| Task | How |
|---|---|
| Update the Edge | Pick a new signed digest, change `image_digest`, apply. ECS stops the old task before starting the new one; the circuit breaker rolls back a failing deploy. Inwom never pushes an image into your account |
| Reduce what is shared | Lower `max_privacy_mode`, remove a source or its bucket grant, apply |
| Pause sharing | Set the ECS service desired count to 0, or **disable the pseudonym KMS key** (the Edge stops deriving keys and exports nothing) |
| Revoke Inwom's access | Revoke the installation in the dashboard, or disable the identity KMS key; delete the stack |
| Uninstall | `terraform destroy` / delete the stack. KMS keys enter their 30-day deletion window. Nothing else remains: no roles Inwom can assume, no trust relationships |
| If Inwom is down | The Edge buffers (bounded, encrypted) and retries; your production traffic is unaffected — the Edge is never on the data path |

## Verify the claims yourself

```bash
# 1. no inbound rule on the Edge security group
aws ec2 describe-security-groups --group-ids <security_group_id> --query 'SecurityGroups[].IpPermissions'   # → []
# 2. task has no public IP / no exec
aws ecs describe-services --cluster <name> --services <name> --query 'services[].{exec:enableECSManagedTags,net:networkConfiguration}'
# 3. the task role cannot do anything outside its matrix
aws iam simulate-principal-policy --policy-source-arn <task_role_arn> \
  --action-names iam:CreateUser sts:AssumeRole ssm:SendCommand ec2:AuthorizeSecurityGroupIngress s3:PutObject lambda:InvokeFunction secretsmanager:GetSecretValue
# → every decision should be "implicitDeny"
```

Questions? Talk to your Inwom contact.
