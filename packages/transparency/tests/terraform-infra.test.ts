import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const terraformRoot = path.join(repoRoot, "infra", "terraform");
const workflowRoot = path.join(repoRoot, ".github", "workflows");

const requiredFiles = [
  "main.tf",
  "rds.tf",
  "elasticache.tf",
  "s3.tf",
  "alb.tf",
  "certificates.tf",
  "cloudfront.tf",
  "iam.tf",
  "waf.tf",
  "otel.tf",
  "ecr.tf",
] as const;

const secretCheckedFiles = [
  ...requiredFiles,
  "env/demo.tfvars.example",
] as const;

const readTerraform = (file: string): string =>
  readFileSync(path.join(terraformRoot, file), "utf8");
const readRepo = (file: string): string =>
  readFileSync(path.join(repoRoot, file), "utf8");
const readWorkflow = (file: string): string =>
  readFileSync(path.join(workflowRoot, file), "utf8");
const expectFragmentsInOrder = (content: string, fragments: string[]): void => {
  let cursor = 0;
  for (const fragment of fragments) {
    const next = content.indexOf(fragment, cursor);
    expect(next, fragment).toBeGreaterThanOrEqual(0);
    cursor = next + fragment.length;
  }
};
const sliceBetween = (content: string, start: string, end: string): string => {
  const startIndex = content.indexOf(start);
  expect(startIndex, start).toBeGreaterThanOrEqual(0);
  const endIndex = content.indexOf(end, startIndex + start.length);
  expect(endIndex, end).toBeGreaterThanOrEqual(0);
  return content.slice(startIndex, endIndex);
};

describe("terraform infrastructure scaffold", () => {
  it("ships the required flat Terraform files", () => {
    for (const file of requiredFiles) {
      expect(existsSync(path.join(terraformRoot, file)), file).toBe(true);
    }
    expect(existsSync(path.join(terraformRoot, ".terraform.lock.hcl"))).toBe(
      true,
    );
  });

  it("declares the production-shaped AWS resources", () => {
    const all = requiredFiles.map(readTerraform).join("\n");

    for (const pattern of [
      /required_version\s+=\s+"= 1\.7\.5"/,
      /version\s+=\s+"= 5\.80\.0"/,
      /resource "aws_db_instance" "postgres"/,
      /engine_version\s+=\s+"16\./,
      /resource "aws_elasticache_replication_group" "redis"/,
      /engine_version\s+=\s+var\.redis_engine_version/,
      /variable "redis_engine_version"[\s\S]*?default\s+=\s+"7\.1"/,
      /Redis OSS 6\+ exposes a single AWS-managed patch stream per major\.minor/,
      /apply_immediately\s+=\s+false/,
      /auto_minor_version_upgrade\s+=\s+false/,
      /maintenance_window\s+=\s+var\.redis_maintenance_window/,
      /snapshot_retention_limit\s+=\s+var\.redis_snapshot_retention_limit/,
      /snapshot_window\s+=\s+var\.redis_snapshot_window/,
      /variable "redis_final_snapshot_identifier_suffix"[\s\S]*?redis_final_snapshot_identifier_suffix must be 8-64/,
      /variable "redis_auth_token_rotation_epoch"[\s\S]*?non-secret Redis AUTH token rotation marker/,
      /final_snapshot_identifier\s+=\s+"\$\{local\.name_prefix\}-redis-final-\$\{var\.redis_final_snapshot_identifier_suffix\}"/,
      /AuthTokenRotationEpoch\s+=\s+var\.redis_auth_token_rotation_epoch/,
      /redis_auth_token_rotation_epoch must carry a non-secret Secrets Manager AWSCURRENT version marker/,
      /kms_key_id\s+=\s+aws_kms_key\.app\.arn/,
      /transit_encryption_mode\s+=\s+"required"/,
      /ignore_changes\s+=\s+\[[\s\S]*?auth_token[\s\S]*?\]/,
      /AuthStrategy\s+=\s+"redis-auth-token-out-of-state-elasticache-api"/,
      /BackupStrategy\s+=\s+"daily-snapshots-plus-final-snapshot"/,
      /TerraformSecrets\s+=\s+"no-redis-auth-token-in-terraform-state"/,
      /AuthReadiness\s+=\s+"deploy-describe-replication-groups-gated"/,
      /RotationEvidence\s+=\s+"redis-auth-token-elasticache-readiness"/,
      /UpdateStrategyDrift\s+=\s+"auth-token-update-strategy-not-ignored"/,
      /AuthTokenEnabledLiveGate\s+=\s+"deploy-dashboard-blocks-unless-AuthTokenEnabled-true"/,
      /AuthTokenCreationMode\s+=\s+"out-of-state-before-service-cutover"/,
      /AuthTokenStatePolicy\s+=\s+"auth-token-material-never-in-terraform-state"/,
      /resource "aws_s3_bucket" "evidence"/,
      /object_lock_enabled\s+=\s+true/,
      /resource "aws_s3_bucket_object_lock_configuration" "evidence"/,
      /backend "s3"/,
      /data "aws_acm_certificate" "public"/,
      /most_recent\s+=\s+true/,
      /statuses\s+=\s+\["ISSUED"\]/,
      /local\.public_certificate_arn/,
      /resource "aws_cloudfront_distribution" "public"/,
      /data "aws_cloudfront_cache_policy" "caching_disabled"/,
      /data "aws_cloudfront_cache_policy" "caching_optimized"/,
      /data "aws_cloudfront_origin_request_policy" "all_viewer"/,
      /resource "aws_cloudfront_origin_request_policy" "host_header_only"/,
      /resource "terraform_data" "public_alb_certificate_san_guard"/,
      /resource "terraform_data" "public_certificate_san_guard"/,
      /verify-acm-san\.mjs/,
      /AIDENID_ACM_CERTIFICATE_VALIDATION_CONTEXT\s+=\s+"phase4-public-alb"/,
      /AIDENID_ACM_CERTIFICATE_EXPECTED_REGION\s+=\s+var\.aws_region/,
      /resource "aws_route53_record" "public_cloudfront_a"/,
      /resource "aws_route53_record" "public_cloudfront_aaaa"/,
      /resource "aws_lb" "app"/,
      /resource "aws_lb_listener" "https"/,
      /certificate_arn\s+=\s+local\.public_certificate_arn/,
      /depends_on\s+=\s+\[[\s\S]*?aws_wafv2_web_acl_association\.app,[\s\S]*?terraform_data\.public_alb_certificate_san_guard,[\s\S]*?\]/,
      /port\s+=\s+443/,
      /ssl_policy\s+=\s+"ELBSecurityPolicy-TLS13-1-2-2021-06"/,
      /resource "aws_wafv2_web_acl" "app"/,
      /resource "aws_wafv2_web_acl_association" "app"/,
      /web_acl_arn\s+=\s+aws_wafv2_web_acl\.app\.arn/,
      /limit\s+=\s+var\.waf_rate_limit/,
      /resource "aws_kms_key" "app"/,
      /deletion_window_in_days\s+=\s+30/,
      /enable_key_rotation\s+=\s+true/,
      /resource "aws_kms_alias" "app"/,
      /name\s+=\s+"alias\/\$\{local\.name_prefix\}-app"/,
      /target_key_id\s+=\s+aws_kms_key\.app\.key_id/,
      /resource "aws_ecr_repository" "service_images"/,
      /image_tag_mutability\s+=\s+"IMMUTABLE"/,
      /force_delete\s+=\s+false/,
      /encryption_type\s+=\s+"KMS"/,
      /kms_key\s+=\s+aws_kms_key\.app\.arn/,
      /scan_on_push\s+=\s+true/,
      /resource "aws_ecr_lifecycle_policy" "service_images"/,
      /Expire untagged images after 7 days/,
      /countNumber\s+=\s+7/,
      /Retain the latest 50 tagged images/,
      /tagPrefixList\s+=\s+\[[\s\S]*?"build-"[\s\S]*?"release-"[\s\S]*?"sha-"[\s\S]*?\]/,
      /countNumber\s+=\s+50/,
      /output "service_ecr_repository_urls"/,
      /data "aws_partition" "current"/,
      /data "aws_caller_identity" "current"/,
      /github_actions_oidc_provider_arn\s+=\s+"arn:\$\{data\.aws_partition\.current\.partition\}:iam::\$\{data\.aws_caller_identity\.current\.account_id\}:oidc-provider\/token\.actions\.githubusercontent\.com"/,
      /resource "aws_iam_role" "github_actions_image_push"/,
      /name\s+=\s+"\$\{local\.name_prefix\}-gha-image-push"/,
      /sts:AssumeRoleWithWebIdentity/,
      /token\.actions\.githubusercontent\.com:aud/,
      /token\.actions\.githubusercontent\.com:sub/,
      /repo:mrrCarter\/aidenid-clearance:ref:refs\/heads\/main/,
      /repo:mrrCarter\/aidenid-clearance:ref:refs\/tags\/release-\*/,
      /data "aws_iam_policy_document" "github_actions_image_push"/,
      /ecr:GetAuthorizationToken/,
      /ecr:BatchCheckLayerAvailability/,
      /ecr:GetDownloadUrlForLayer/,
      /ecr:InitiateLayerUpload/,
      /ecr:UploadLayerPart/,
      /ecr:CompleteLayerUpload/,
      /ecr:PutImage/,
      /aws_ecr_repository\.service_images\["control-plane"\]\.arn/,
      /aws_ecr_repository\.service_images\["dashboard"\]\.arn/,
      /aws_ecr_repository\.service_images\["otel-collector"\]\.arn/,
      /aws_ecr_repository\.service_images\["verifier"\]\.arn/,
      /resource "aws_iam_role_policy" "github_actions_image_push"/,
      /output "github_actions_image_push_role_arn"/,
      /variable "enable_nat_egress"/,
      /variable "enable_private_vpc_endpoints"/,
      /count\s+=\s+var\.enable_nat_egress \? length\(aws_subnet\.public\) : 0/,
      /dynamic "route"/,
      /var\.enable_nat_egress \? \[1\] : \[\]/,
      /resource "aws_vpc_endpoint" "interface"/,
      /resource "aws_vpc_endpoint" "s3"/,
      /data "aws_prefix_list" "s3_gateway"/,
      /enable_private_vpc_endpoints or allowed_egress_prefix_list_ids/,
      /resource "aws_ecs_service" "control_plane"/,
      /resource "aws_ecs_service" "verifier"/,
      /resource "aws_security_group" "ecs_control_plane"/,
      /resource "aws_security_group" "ecs_dashboard"/,
      /resource "aws_security_group" "ecs_verifier"/,
      /resource "aws_security_group" "ecs_otel"/,
      /resource "aws_service_discovery_private_dns_namespace" "main"/,
      /resource "aws_service_discovery_service" "control_plane"/,
      /resource "aws_service_discovery_service" "otel_collector"/,
      /resource "aws_iam_role" "control_plane_task"/,
      /resource "aws_iam_role" "dashboard_task"/,
      /resource "aws_iam_role" "verifier_task"/,
      /resource "aws_iam_role" "otel_task"/,
      /resource "aws_ssm_parameter" "otel_collector_config"/,
      /resource "aws_secretsmanager_secret" "control_plane_signing_key"/,
      /resource "aws_secretsmanager_secret" "operator_tokens"/,
      /resource "aws_secretsmanager_secret" "dashboard_operator_token"/,
      /resource "aws_secretsmanager_secret" "verifier_site_api_key"/,
      /resource "aws_secretsmanager_secret" "verifier_upstream_api_key"/,
      /resource "aws_secretsmanager_secret" "redis_auth_token"/,
      /resource "aws_secretsmanager_secret" "otel_otlp_auth"/,
      /resource "aws_cloudwatch_log_group" "otel"/,
    ]) {
      expect(all).toMatch(pattern);
    }
    expect(readTerraform(".terraform.lock.hcl")).toMatch(
      /provider "registry\.terraform\.io\/hashicorp\/aws"[\s\S]*?version\s+=\s+"5\.80\.0"/,
    );
    expect(readTerraform("main.tf")).not.toContain('"ec2messages"');
    expect(readTerraform("README.md")).toContain(
      "does not manage the ElastiCache `auth_token` argument",
    );
    expect(readTerraform("elasticache.tf")).not.toContain(
      "auth_token                 = var.redis_auth_token",
    );
    const ecr = readTerraform("ecr.tf");
    expect(ecr).not.toContain("repo:mrrCarter/aidenid-clearance:*");
    expect(ecr).not.toContain("pull_request");
    expect(ecr).not.toContain('"ecr:*"');
    expect(ecr).not.toContain('"sts:AssumeRole"');
    expect(ecr).not.toMatch(/"(?:s3|secretsmanager):/);
  });

  it("requires digest-pinned application images and dedicated hostnames", () => {
    const main = readTerraform("main.tf");
    const tfvars = readTerraform("env/demo.tfvars.example");

    for (const variable of [
      "control_plane_image",
      "dashboard_image",
      "verifier_image",
      "otel_collector_image",
    ]) {
      expect(main).toMatch(
        new RegExp(
          `variable "${variable}"[\\s\\S]*?repository@sha256:<64-hex-digest>`,
        ),
      );
      expect(tfvars).toMatch(
        new RegExp(
          `${variable}\\s*=\\s*"[^"]*REPLACE_ME[^"]+@sha256:REPLACE_ME_64_HEX_DIGEST`,
        ),
      );
      expect(main).toMatch(
        new RegExp(
          `variable "${variable}"[\\s\\S]*?111122223333[\\s\\S]*?repeated-character digest examples`,
        ),
      );
      expect(tfvars).not.toMatch(new RegExp(`${variable} = "[^"]+:demo"`));
    }
    expect(tfvars).toContain("intentionally non-runnable");
    expect(tfvars).toContain("REPLACE_ME_ACCOUNT_ID");
    expect(tfvars).not.toContain("111122223333");
    expect(tfvars).not.toMatch(/@sha256:[0-9a-f]{64}/);

    expect(main).toMatch(/variable "dashboard_hostname"/);
    expect(main).toMatch(/variable "control_plane_hostname"/);
    expect(main).toMatch(/variable "verifier_hostname"/);
    expect(main).toMatch(/variable "public_certificate_domain_name"/);
    expect(main).toMatch(/variable "enable_public_cloudfront"/);
    expect(main).toMatch(/variable "enable_public_route53_alias_records"/);
    expect(main).toMatch(/variable "public_route53_zero_weight_ack"/);
    expect(main).toMatch(
      /variable "alb_certificate_arn"[\s\S]*?Leave empty to look up/,
    );
    expect(main).toMatch(/variable "clearance_site_id"/);
    expect(main).toMatch(/variable "control_plane_issuer"/);
    expect(main).toMatch(/variable "verifier_upstream_url"/);
    expect(main).toContain("api.aidenid.com");
    expect(main).toContain("swarm.aidenid.com");
    expect(tfvars).toMatch(
      /dashboard_hostname\s+=\s+"dashboard\.example\.com"/,
    );
    expect(tfvars).toMatch(
      /control_plane_hostname\s+=\s+"clearance-api\.example\.com"/,
    );
    expect(tfvars).toMatch(/verifier_hostname\s+=\s+"verify\.example\.com"/);
    expect(tfvars).toMatch(
      /public_certificate_domain_name\s+=\s+"dashboard\.example\.com"/,
    );
    expect(tfvars).toMatch(/enable_public_cloudfront\s+=\s+false/);
    expect(tfvars).toMatch(/enable_public_route53_alias_records\s+=\s+false/);
    expect(tfvars).toMatch(/public_route53_record_weight\s+=\s+0/);
    expect(tfvars).toMatch(/clearance_site_id\s+=\s+"sit_aidenid_com"/);
    expect(tfvars).toMatch(
      /control_plane_issuer\s+=\s+"https:\/\/api\.aidenid\.com"/,
    );
    expect(tfvars).toMatch(
      /verifier_upstream_url\s+=\s+"https:\/\/aidenid\.com"/,
    );
    expect(main).toContain("verifier_control_plane_operator_token_json_key");
    expect(tfvars).toMatch(
      /verifier_control_plane_operator_token_json_key\s+=\s+"verifier_control_plane_api_key"/,
    );
    expect(main).toContain(
      "allowed_ingress_cidrs must not include 0.0.0.0/0 or ::/0",
    );
    expect(main).toContain(
      "allowed_ingress_cidrs must be no broader than /24 for IPv4 or /64 for IPv6",
    );
    expect(main).toContain("Demo-only narrow CIDR ranges");
    expect(main).toMatch(/variable "allowed_ingress_cidrs_exception_ticket"/);
    expect(main).toMatch(/variable "allowed_ingress_cidrs_expires_at"/);
    expect(main).toContain(
      "allowed_ingress_cidrs_exception_ticket must be empty or an incident/change ticket",
    );
    expect(main).toContain(
      "allowed_ingress_cidrs_expires_at must be empty or a future UTC ISO-8601",
    );
    expect(main).toContain(
      'trimspace(var.allowed_ingress_cidrs_expires_at) == "" ? true',
    );
    expect(main).toContain(
      "timecmp(trimspace(var.allowed_ingress_cidrs_expires_at), timestamp()) == 1",
    );
    expect(main).toMatch(/variable "allowed_ingress_prefix_list_ids"/);
    expect(main).toMatch(/variable "allowed_egress_prefix_list_ids"/);
    expect(main).toContain("AWS prefix list IDs like pl-1234abcd");
    expect(main).toContain("can(cidrhost(cidr, 0))");
    expect(main).toMatch(/variable "waf_rate_limit"/);
    expect(main).toContain(
      "waf_rate_limit must be between 100 and 2000000000 requests per 5-minute window.",
    );
    expect(tfvars).toMatch(/waf_rate_limit\s+=\s+2000/);
    expect(tfvars).toMatch(/allowed_ingress_cidrs\s+=\s+\[\]/);
    expect(tfvars).toContain("future UTC expiry no more than 24 hours");
    expect(tfvars).toMatch(/allowed_ingress_cidrs_exception_ticket\s+=\s+""/);
    expect(tfvars).toMatch(/allowed_ingress_cidrs_expires_at\s+=\s+""/);
    expect(tfvars).toMatch(/allowed_ingress_prefix_list_ids\s+=\s+\[\]/);
    expect(tfvars).toMatch(/allowed_egress_prefix_list_ids\s+=\s+\[\]/);
  });

  it("wires the public dashboard to the live control plane without leaking secrets", () => {
    const all = requiredFiles.map(readTerraform).join("\n");

    expect(all).toMatch(
      /control_plane_service_url\s+=\s+"http:\/\/control-plane\.\$\{local\.service_discovery_namespace\}:\$\{var\.service_backend_port\}"/,
    );
    expect(all).toMatch(
      /resource "aws_security_group" "ecs_control_plane"[\s\S]*?Dashboard BFF HTTP to control-plane API[\s\S]*?from_port\s+=\s+var\.service_backend_port[\s\S]*?to_port\s+=\s+var\.service_backend_port[\s\S]*?security_groups\s+=\s+\[aws_security_group\.ecs_dashboard\.id\]/,
    );
    expect(all).toContain("Dashboard BFF HTTP to control-plane API");
    expect(all).not.toContain("control_plane_dashboard_bff_port");
    expect(all).not.toMatch(/resource "aws_security_group" "ecs_tasks"/);
    expect(all).not.toMatch(/self\s+=\s+true/);
    expect(all).toMatch(
      /resource "aws_ecs_service" "control_plane"[\s\S]*?security_groups\s+=\s+\[aws_security_group\.ecs_control_plane\.id\]/,
    );
    expect(all).toMatch(
      /resource "aws_ecs_service" "dashboard"[\s\S]*?security_groups\s+=\s+\[aws_security_group\.ecs_dashboard\.id\]/,
    );
    expect(all).toMatch(
      /resource "aws_ecs_service" "verifier"[\s\S]*?security_groups\s+=\s+\[aws_security_group\.ecs_verifier\.id\]/,
    );
    expect(all).toMatch(
      /resource "aws_ecs_service" "control_plane"[\s\S]*?service_registries\s+\{[\s\S]*?aws_service_discovery_service\.control_plane\.arn/,
    );
    expect(all).toContain("AIDENID_CONTROL_PLANE_URL");
    expect(all).toMatch(
      /\{ name = "AIDENID_DASHBOARD_REQUIRE_LIVE_DATA", value = "true" \}/,
    );
    expect(all).toContain('"PORT", value = tostring(var.service_backend_port)');
    expect(all).toContain("AIDENID_CONTROL_PLANE_ISSUER");
    expect(all).not.toContain("AIDENID_CONTROL_PLANE_DASHBOARD_BFF_PORT");
    expect(all).toContain("AIDENID_DASHBOARD_SITE_ID");
    expect(all).toContain("AIDENID_DASHBOARD_OPERATOR_ACTOR_ID");
    expect(all).toContain("AIDENID_OPERATOR_TOKEN");
    expect(all).toContain(
      "aws_secretsmanager_secret.dashboard_operator_token.arn",
    );
    expect(all).toContain("AIDENID_REDIS_HOST");
    expect(all).toContain("AIDENID_REDIS_PORT");
    expect(all).toContain("AIDENID_REDIS_TLS");
    expect(all).toContain("AIDENID_REDIS_AUTH_TOKEN");
    expect(all).toContain(
      "${aws_secretsmanager_secret.redis_auth_token.arn}:auth_token::",
    );
  });

  it("injects RDS and operator secrets into ECS instead of committing them", () => {
    const all = requiredFiles.map(readTerraform).join("\n");

    expect(all).toContain(
      "master_user_secret_kms_key_id = aws_kms_key.app.arn",
    );
    expect(all).toContain("AIDENID_CONTROL_PLANE_DATABASE_HOST");
    expect(all).toContain("AIDENID_CONTROL_PLANE_DATABASE_PORT");
    expect(all).toContain("AIDENID_CONTROL_PLANE_DATABASE_NAME");
    expect(all).toContain("AIDENID_CONTROL_PLANE_DATABASE_USER");
    expect(all).toContain("AIDENID_CONTROL_PLANE_DATABASE_SSLMODE");
    expect(all).toContain("AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT");
    expect(all).toContain(
      '{ name = "AIDENID_CONTROL_PLANE_DATABASE_SSLMODE", value = "verify-full" }',
    );
    expect(all).toContain(
      '{ name = "AIDENID_CONTROL_PLANE_DATABASE_SSLROOTCERT", value = "/app/certs/rds-global-bundle.pem" }',
    );
    expect(all).toContain("AIDENID_CONTROL_PLANE_DATABASE_PASSWORD");
    expect(all).toContain(
      "${aws_db_instance.postgres.master_user_secret[0].secret_arn}:password::",
    );
    expect(all).toContain("ReadAwsManagedInjectedSecrets");
    expect(all).toContain("direct_secretsmanager_arns");
    expect(all).toContain("tagged_secretsmanager_arns");
    expect(all).toContain("secretsmanager:ResourceTag/Project");
    expect(all).toContain("secretsmanager:ResourceTag/Environment");
    expect(all).toContain("secretsmanager:ResourceTag/ManagedBy");
    expect(all).toContain("resources = each.value.tagged_secretsmanager_arns");
    expect(all).toContain("AIDENID_OPERATOR_TOKENS");
    expect(all).toContain("aws_secretsmanager_secret.operator_tokens.arn");
    expect(all).toContain(
      "aws_secretsmanager_secret.verifier_site_api_key.arn",
    );
    expect(all).toContain(
      "aws_secretsmanager_secret.verifier_upstream_api_key.arn",
    );
    expect(all).toContain("AIDENID_VERIFIER_SITE_API_KEY");
    expect(all).toContain("AIDENID_CONTROL_PLANE_API_KEY");
    expect(all).toContain(
      "${aws_secretsmanager_secret.operator_tokens.arn}:${var.verifier_control_plane_operator_token_json_key}::",
    );
    expect(all).toContain("aws_secretsmanager_secret.redis_auth_token.arn");
    expect(all).not.toContain(
      'resource "aws_secretsmanager_secret_version" "redis_auth_token"',
    );
    expect(all).toContain('sid = "AbortEvidenceMultipartUploads"');
    expect(all).toContain('sid = "WriteTaggedEncryptedEvidenceObjects"');
    expect(all).toContain(
      "${aws_s3_bucket.evidence.arn}/events/${var.environment}/*",
    );
    expect(all).toContain('"s3:PutObject"');
    expect(all).not.toContain('"s3:PutObjectRetention"');
    expect(all).not.toContain('"s3:PutObjectTagging"');
    expect(all).toContain('"s3:AbortMultipartUpload"');
    expect(all).toContain("s3:x-amz-server-side-encryption");
    expect(all).toContain("s3:x-amz-server-side-encryption-aws-kms-key-id");
    expect(all).toContain("s3:RequestObjectTag/aidenid-evidence-kind");
    expect(all).toContain("control-plane-event");
    expect(all).not.toContain('"s3:GetObject"');
    expect(all).not.toContain('"s3:ListBucket"');
    expect(all).toContain("aws_ssm_parameter.otel_collector_config.arn");
    expect(all).toContain("aws_secretsmanager_secret.otel_otlp_auth.arn");
    expect(all).toContain("ssm:GetParameters");
    expect(all).toContain('data "aws_iam_policy_document" "app_kms"');
    expect(all).toContain('sid = "AllowCloudWatchLogsUseForEcsLogGroups"');
    expect(all).toContain(
      'identifiers = ["logs.${var.aws_region}.amazonaws.com"]',
    );
    expect(all).toContain("kms:EncryptionContext:aws:logs:arn");
    expect(all).toContain("log-group:/ecs/${local.name_prefix}/*");
    expect(all).toContain("kms:ViaService");
    expect(all).toContain("kms:EncryptionContext:SecretARN");
    expect(all).toContain("kms:EncryptionContext:PARAMETER_ARN");
    expect(all).toContain("local.control_plane_runtime_secret_arns");
    expect(all).toContain("local.verifier_runtime_secret_arns");
    expect(all).toContain("local.kms_secretsmanager_via_service");
    expect(all).toContain("ecs_execution_role_bindings");
    expect(all).toContain("AidenIDRuntimeSecretScope");
    expect(all).toContain("AidenIDRuntimeSecretServiceControlPlane");
    expect(all).toContain("AidenIDRuntimeSecretServiceDashboard");
    expect(all).toContain("AidenIDRuntimeSecretServiceVerifier");
    expect(all).toContain("AidenIDRuntimeSecretServiceOtel");
    expect(all).toContain("runtime_secret_service_tag");
    expect(all).toContain("DenyUntaggedRuntimeSecretScope");
    expect(all).toContain("resources = each.value.tagged_secretsmanager_arns");
    expect(all).toContain("resources = each.value.direct_secretsmanager_arns");
    expect(all).toContain(
      "resources = local.control_plane_runtime_secret_arns",
    );
    expect(all).toContain("resources = local.verifier_runtime_secret_arns");
    expect(all).not.toContain("StringLikeIfExists");
    expect(all).not.toContain("StringNotLike");
    expect(all).not.toContain(
      'variable = "secretsmanager:ResourceTag/AidenIDRuntimeSecretScope"',
    );
    expect(all).not.toContain('values   = ["*control-plane*"]');
    expect(all).not.toContain('values   = ["*verifier*"]');
    expect(all).toContain("DenyMismatchedRuntimeSecretScope");
    expect(all).toContain("StringEquals");
    expect(all).toContain("StringNotEquals");
    expect(all).toContain(
      'variable = "secretsmanager:ResourceTag/${each.value.runtime_secret_service_tag}"',
    );
    expect(all).toContain("values   = [each.value.name]");
    expect(all).toContain("control-plane+dashboard+verifier+otel");
    expect(all).toContain("control-plane+verifier");
    expect(all).not.toContain("control-plane,dashboard,verifier,otel");
    expect(all).not.toContain("control-plane,verifier");
    expect(all).toContain('aws_iam_role.ecs_execution["control_plane"].arn');
    expect(all).toContain('aws_iam_role.ecs_execution["dashboard"].arn');
    expect(all).toContain('aws_iam_role.ecs_execution["verifier"].arn');
    expect(all).toContain('aws_iam_role.ecs_execution["otel"].arn');
    expect(all).toContain("for_each = local.ecs_execution_role_bindings");
    expect(all).toMatch(
      /resource "aws_iam_role_policy" "ecs_execution_secrets"/,
    );
  });

  it("keeps the OTel collector config out of raw ECS task environment values", () => {
    const otel = readTerraform("otel.tf");
    const taskDefinition = otel.slice(
      otel.indexOf("container_definitions = jsonencode(["),
    );
    const collectorConfig = readRepo("infra/otel/collector.yaml");

    expect(otel).toContain('type   = "SecureString"');
    expect(otel).toContain('name      = "AOT_CONFIG_CONTENT"');
    expect(otel).toContain('name      = "OTEL_RECEIVER_BEARER_TOKEN"');
    expect(otel).toContain(
      "valueFrom = aws_ssm_parameter.otel_collector_config.arn",
    );
    expect(otel).toContain(
      'valueFrom = "${aws_secretsmanager_secret.otel_otlp_auth.arn}:token::"',
    );
    expect(otel).not.toMatch(
      /environment\s*=\s*\[[\s\S]*?AOT_CONFIG_CONTENT[\s\S]*?\]/,
    );
    expect(taskDefinition).not.toMatch(
      /value\s*=\s*file\("\$\{path\.module\}\/\.\.\/otel\/collector\.yaml"\)/,
    );
    expect(collectorConfig).toContain("bearertokenauth/otlp");
    expect(collectorConfig).toContain("auth:");
    expect(collectorConfig).toContain("authenticator: bearertokenauth/otlp");
    expect(collectorConfig).toContain("${env:OTEL_RECEIVER_BEARER_TOKEN}");
    expect(collectorConfig).toContain("debug:");
    expect(collectorConfig).toContain("exporters: [debug]");
    expect(collectorConfig).not.toContain("logging:");
    expect(collectorConfig).not.toContain("exporters: [logging]");
    expect(collectorConfig).toContain("timeout: 5s");
    expect(collectorConfig).toContain("send_batch_size: 512");
    expect(collectorConfig).toContain("send_batch_max_size: 1024");
    expect(collectorConfig).toContain("memory_limiter:");
    expect(collectorConfig).not.toMatch(/Bearer [A-Za-z0-9._~+/=-]{16,}/);
  });

  it("wires the verifier wrapper runtime contract into ECS", () => {
    const all = requiredFiles.map(readTerraform).join("\n");
    const main = readTerraform("main.tf");
    const alb = readTerraform("alb.tf");
    const readme = readTerraform("README.md");
    const spec = readRepo("SPEC.md");

    expect(main).toContain(
      'target_group_name_prefix    = substr(replace(local.name_prefix, "aidenid-clearance", "aidclr"), 0, 20)',
    );
    expect(alb).toContain(
      'name        = "${local.target_group_name_prefix}-ctrl"',
    );
    expect(alb).toContain(
      'name        = "${local.target_group_name_prefix}-dash"',
    );
    expect(alb).toContain(
      'name        = "${local.target_group_name_prefix}-vrfy"',
    );
    expect(readme).toContain("AWS limits target-group names to 32 characters");
    expect(readme).toContain(
      'ALB target groups and dashboard-to-control-plane BFF traffic use `protocol = "HTTP"`',
    );
    expect(spec).toContain(
      "The production Terraform stack terminates public TLS at the ALB HTTPS listener.",
    );
    expect(spec).toContain(
      "Dashboard BFF calls to the control plane use `http://control-plane.<service-discovery-namespace>:<service_backend_port>`",
    );

    expect(all).toContain("local.verifier_environment");
    for (const name of [
      "AIDENID_VERIFIER_SITE_ID",
      "AIDENID_VERIFIER_UPSTREAM_URL",
      "AIDENID_VERIFIER_ALLOWED_UPSTREAM_ORIGINS",
      "AIDENID_VERIFIER_MODE",
      "AIDENID_CONTROL_PLANE_URL",
      "AIDENID_OPERATOR_AWAIT_TIMEOUT_MS",
      "AIDENID_VERIFIER_OPERATOR_TIMEOUT_FALLBACK",
      "AIDENID_VERIFIER_UPSTREAM_TIMEOUT_MS",
      "AIDENID_VERIFIER_TRUST_FORWARDED_PROTO",
      "AIDENID_VERIFIER_LOCAL_FINGERPRINT_ENABLED",
      "AIDENID_VERIFIER_STATIC_OPERATOR_REPUTATION_ENABLED",
      "AIDENID_VERIFIER_SITE_API_KEY",
      "AIDENID_CONTROL_PLANE_API_KEY",
    ]) {
      expect(all).toContain(name);
    }
    expect(all).toContain("verifier_upstream_api_key_secret_enabled");
    expect(all).toContain("AIDENID_VERIFIER_UPSTREAM_API_KEY");
    expect(all).toContain("var.verifier_upstream_api_key_secret_enabled ? [");
    expect(all).toContain(
      "${aws_secretsmanager_secret.operator_tokens.arn}:${var.verifier_control_plane_operator_token_json_key}::",
    );
    expect(all).toContain(
      'AidenIDRuntimeSecretServiceVerifier     = "verifier"',
    );
    expect(readme).toContain(
      "`AIDENID_CONTROL_PLANE_API_KEY` is injected from the top-level",
    );
  });

  it("forces HTTP traffic onto the TLS listener", () => {
    const alb = readTerraform("alb.tf");
    const cloudfront = readTerraform("cloudfront.tf");
    const main = readTerraform("main.tf");

    expect(alb).not.toMatch(
      /from_port\s+=\s+80[\s\S]*?cidr_blocks\s+=\s+var\.allowed_ingress_cidrs/,
    );
    expect(alb).toContain(
      "allowed_ingress_cidrs may only be non-empty in demo",
    );
    expect(alb).toContain(
      "Public ALB ingress requires either demo-only allowed_ingress_cidrs or managed allowed_ingress_prefix_list_ids",
    );
    expect(alb).toContain(
      "Public ALB ingress must use exactly one source mode",
    );
    expect(alb).toContain(
      "(length(var.allowed_ingress_cidrs) == 0) != (length(local.effective_ingress_prefix_list_ids) == 0)",
    );
    expect(alb).toContain(
      "allowed_ingress_cidrs must be reviewed narrow CIDRs even in demo",
    );
    expect(alb).toContain(
      "Demo-only allowed_ingress_cidrs require allowed_ingress_cidrs_exception_ticket and allowed_ingress_cidrs_expires_at",
    );
    expect(alb).toContain("IngressExceptionTicket");
    expect(alb).toContain("IngressExceptionExpiresAt");
    expect(alb).toContain('cidr != "0.0.0.0/0"');
    expect(alb).toContain('cidr != "::/0"');
    expect(alb).toContain('tonumber(split("/", cidr)[1]) >= 24');
    expect(alb).toContain('tonumber(split("/", cidr)[1]) >= 64');
    expect(alb).toContain(
      "Public ALB readiness requires the environment-local REGIONAL WAF web ACL before ingress can be exposed.",
    );
    expect(alb).toContain(
      "ALB WAF association must bind the expected environment-local WAF ACL ARN.",
    );
    expect(alb).toMatch(
      /resource "aws_wafv2_web_acl_association" "app"[\s\S]*?web_acl_arn\s+=\s+aws_wafv2_web_acl\.app\.arn[\s\S]*?precondition/,
    );
    expect(alb).toMatch(
      /resource "aws_lb_listener" "https"[\s\S]*?depends_on\s+=\s+\[[\s\S]*?aws_wafv2_web_acl_association\.app,[\s\S]*?terraform_data\.public_alb_certificate_san_guard,[\s\S]*?\]/,
    );
    expect(alb).toMatch(
      /resource "aws_lb_listener" "http"[\s\S]*?port\s+=\s+80[\s\S]*?protocol\s+=\s+"HTTP"/,
    );
    expect(alb).toMatch(
      /default_action\s+\{[\s\S]*?type\s+=\s+"redirect"[\s\S]*?redirect\s+\{/,
    );
    expect(alb).toMatch(
      /redirect\s+\{[\s\S]*?port\s+=\s+"443"[\s\S]*?protocol\s+=\s+"HTTPS"[\s\S]*?status_code\s+=\s+"HTTP_301"/,
    );
    expect(alb).toMatch(
      /resource "aws_lb_listener" "https"[\s\S]*?protocol\s+=\s+"HTTPS"[\s\S]*?ssl_policy\s+=\s+"ELBSecurityPolicy-TLS13-1-2-2021-06"/,
    );
    expect(alb).toContain(
      'resource "aws_security_group" "alb_managed_prefix_list_ingress"',
    );
    expect(alb).toContain(
      "effective_ingress_prefix_list_ids   = concat(var.allowed_ingress_prefix_list_ids, local.cloudflare_ingress_prefix_list_ids)",
    );
    expect(alb).toContain(
      "alb_primary_ingress_prefix_list_ids = length(local.effective_ingress_prefix_list_ids) > 0 ? [local.effective_ingress_prefix_list_ids[0]] : []",
    );
    expect(alb).toContain(
      "alb_sharded_ingress_prefix_list_ids = length(local.effective_ingress_prefix_list_ids) > 1 ? { for index, id in slice(local.effective_ingress_prefix_list_ids, 1, length(local.effective_ingress_prefix_list_ids)) : tostring(index + 1) => id } : {}",
    );
    expect(alb).toContain(
      "private_s3_gateway_prefix_list_ids  = var.enable_private_vpc_endpoints ? [data.aws_prefix_list.s3_gateway[0].id] : []",
    );
    expect(alb).toContain(
      "app_tls_egress_prefix_list_ids      = toset(concat(var.allowed_egress_prefix_list_ids, local.private_s3_gateway_prefix_list_ids))",
    );
    expect(alb).toContain(
      "for_each = local.alb_primary_ingress_prefix_list_ids",
    );
    expect(alb).toContain(
      "for_each = local.alb_sharded_ingress_prefix_list_ids",
    );
    expect(alb).toContain("IngressPrefixListSharded");
    expect(alb).toContain("prefix_list_ids = [ingress.value]");
    expect(alb).toContain("prefix_list_ids = [each.value]");
    expect(alb).toMatch(
      /security_groups\s+=\s+concat\([\s\S]*?\[aws_security_group\.alb\.id\][\s\S]*?aws_security_group\.alb_managed_prefix_list_ingress/,
    );
    expect(alb).toContain("allowed_egress_prefix_list_ids");
    expect(alb).toContain("for_each = local.app_tls_egress_prefix_list_ids");
    expect(alb).toContain("approved AWS/API or S3 gateway egress over TLS");
    expect(main).toContain('variable "service_backend_port"');
    expect(main).toContain(
      "service_backend_port must be between 1024 and 65535",
    );
    expect(main).toContain(
      "Backend HTTP port used consistently by ALB target groups",
    );
    expect(main).toContain('variable "alb_health_check_timeout_seconds"');
    expect(main).toContain('variable "alb_health_check_unhealthy_threshold"');
    expect(main).toContain(
      "alb_health_check_timeout_seconds must be between 5 and 119 seconds",
    );
    expect(alb).toContain(
      "var.alb_health_check_timeout_seconds < var.alb_health_check_interval_seconds",
    );
    expect(main).toContain("service_desired_count must be at least 2");
    expect(alb).toContain("from_port   = var.service_backend_port");
    expect(alb).toContain("to_port     = var.service_backend_port");
    expect(alb).toContain("port        = var.service_backend_port");
    expect(alb).toContain("containerPort = var.service_backend_port");
    expect(alb).toContain("container_port   = var.service_backend_port");
    expect(alb).not.toContain("var.control_plane_dashboard_bff_port");
    expect(alb).not.toMatch(/port\s+=\s+3000/);
    expect(alb).not.toContain("containerPort" + " = 3000");
    expect(alb).not.toContain("container_port" + "   = 3000");
    expect(alb).not.toContain('cidr_blocks = ["0.0.0.0/0"]');
    expect(alb).toMatch(
      /resource "aws_lb_target_group" "control_plane"[\s\S]*?protocol\s+=\s+"HTTP"/,
    );
    expect(alb).toMatch(
      /resource "aws_lb_target_group" "control_plane"[\s\S]*?health_check\s+\{[\s\S]*?path\s+=\s+"\/readyz"/,
    );
    expect(alb).toMatch(
      /resource "aws_lb_target_group" "dashboard"[\s\S]*?protocol\s+=\s+"HTTP"/,
    );
    expect(alb).toMatch(
      /resource "aws_lb_target_group" "verifier"[\s\S]*?protocol\s+=\s+"HTTP"/,
    );
    expect(alb).toMatch(/health_check\s+\{[\s\S]*?protocol\s+=\s+"HTTP"/);
    for (const targetGroup of ["control_plane", "dashboard", "verifier"]) {
      expect(alb).toMatch(
        new RegExp(
          `resource "aws_lb_target_group" "${targetGroup}"[\\s\\S]*?health_check\\s+\\{[\\s\\S]*?matcher\\s+=\\s+"200-399"[\\s\\S]*?interval\\s+=\\s+var\\.alb_health_check_interval_seconds[\\s\\S]*?timeout\\s+=\\s+var\\.alb_health_check_timeout_seconds[\\s\\S]*?healthy_threshold\\s+=\\s+var\\.alb_health_check_healthy_threshold[\\s\\S]*?unhealthy_threshold\\s+=\\s+var\\.alb_health_check_unhealthy_threshold`,
        ),
      );
    }
    expect(alb).toContain(
      "interval            = var.alb_health_check_interval_seconds",
    );
    expect(alb).toContain(
      "timeout             = var.alb_health_check_timeout_seconds",
    );
    expect(alb).toContain(
      "healthy_threshold   = var.alb_health_check_healthy_threshold",
    );
    expect(alb).toContain(
      "unhealthy_threshold = var.alb_health_check_unhealthy_threshold",
    );
    expect(alb).not.toMatch(/timeout\s+=\s+5/);
    expect(alb).not.toMatch(/unhealthy_threshold\s+=\s+3/);
    expect(alb).toMatch(
      /resource "aws_lb_listener" "https"[\s\S]*?default_action\s+\{[\s\S]*?type\s+=\s+"fixed-response"[\s\S]*?status_code\s+=\s+"404"/,
    );
    expect(alb).toMatch(
      /resource "aws_lb_listener_rule" "dashboard"[\s\S]*?host_header\s+\{[\s\S]*?values\s+=\s+\[var\.dashboard_hostname\]/,
    );
    const controlPlaneRule = sliceBetween(
      alb,
      'resource "aws_lb_listener_rule" "control_plane"',
      'resource "aws_lb_listener_rule" "verifier"',
    );
    const verifierRule = sliceBetween(
      alb,
      'resource "aws_lb_listener_rule" "verifier"',
      'resource "aws_ecs_cluster" "main"',
    );
    expect(controlPlaneRule).toMatch(
      /host_header\s+\{[\s\S]*?values\s+=\s+\[var\.control_plane_hostname\]/,
    );
    expect(verifierRule).toMatch(
      /host_header\s+\{[\s\S]*?values\s+=\s+\[var\.verifier_hostname\]/,
    );
    expect(controlPlaneRule).not.toContain("path_pattern");
    expect(verifierRule).not.toContain("path_pattern");
    expect(alb).not.toContain('values = ["/v1/*"]');
    expect(alb).not.toContain('values = ["/verify/*"]');
    expect(cloudfront).toContain("Managed-CachingDisabled");
    expect(cloudfront).toContain("Managed-CachingOptimized");
    expect(cloudfront).toContain("Managed-AllViewer");
    expect(cloudfront).toContain('items = ["Host"]');
    expectFragmentsInOrder(cloudfront, [
      "default_cache_behavior {",
      'allowed_methods          = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]',
      "cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id",
      "origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id",
    ]);
    expectFragmentsInOrder(cloudfront, [
      "ordered_cache_behavior {",
      'path_pattern             = "/_next/static/*"',
      "cache_policy_id          = data.aws_cloudfront_cache_policy.caching_optimized.id",
      "origin_request_policy_id = one(aws_cloudfront_origin_request_policy.host_header_only[*].id)",
    ]);
    expect(cloudfront).toContain(
      "CloudFront viewer certificates must be ACM certificates in us-east-1.",
    );
    expect(cloudfront).toContain(
      "Zero-weight Route53 aliases require public_route53_zero_weight_ack",
    );
    expect(cloudfront).toContain(
      "all-zero weighted record sets can still receive traffic",
    );
    expectFragmentsInOrder(cloudfront, [
      'resource "aws_route53_record" "public_cloudfront_a"',
      "weighted_routing_policy {",
      "weight = var.public_route53_record_weight",
      "alias {",
      "name                   = one(aws_cloudfront_distribution.public[*].domain_name)",
    ]);
    expectFragmentsInOrder(cloudfront, [
      'resource "aws_route53_record" "public_cloudfront_aaaa"',
      'type           = "AAAA"',
    ]);
  });

  it("documents the Phase 4 CloudFront and weighted DNS cutover ceremony", () => {
    const runbook = readRepo("tasks/runbooks/phase4-cutover.md");

    expect(runbook).toContain("dashboard.aidenid.com");
    expect(runbook).toContain("clearance-api.aidenid.com");
    expect(runbook).toContain("verify.aidenid.com");
    expect(runbook).toContain("Do not repoint `api.aidenid.com`");
    expect(runbook).toContain(".tmp/phase2c/production-core.tfvars");
    expect(runbook).toContain("operator-managed and intentionally untracked");
    expect(runbook).toContain(
      "Select-String -Path .tmp/phase2c/production-core.tfvars",
    );
    expect(runbook).toContain("scripts/terraform/verify-acm-san.mjs");
    expect(runbook).toContain("enable_public_cloudfront            = true");
    expect(runbook).toContain("enable_public_route53_alias_records = false");
    expect(runbook).toContain("enable_public_route53_alias_records = true");
    expect(runbook).toContain("public_route53_record_weight        = 1");
    expect(runbook).toContain("public_route53_zero_weight_ack");
    expect(runbook).toContain("curl --connect-to");
    expect(runbook).toContain("https://dashboard.aidenid.com/api/status");
    expect(runbook).toContain("https://clearance-api.aidenid.com/v1/decisions");
    expect(runbook).toContain(
      "https://verify.aidenid.com/verify/cutover-smoke",
    );
    expect(runbook).toContain("https://clearance-api.aidenid.com/healthz");
    expect(runbook).toContain("https://verify.aidenid.com/healthz");
    expect(runbook).toContain("1 -> 10 -> 50 -> 100");
    expect(runbook).toContain("Fast rollback is a Route53 weight reduction");
    expect(runbook).toContain("No Terraform apply may run");
  });

  it("documents rollback and enables ECS automatic rollback controls", () => {
    const all = requiredFiles.map(readTerraform).join("\n");
    const readme = readTerraform("README.md");

    expect(
      all.match(
        /deployment_circuit_breaker\s+\{[\s\S]*?enable\s+=\s+true[\s\S]*?rollback\s+=\s+true/g,
      ),
    ).toHaveLength(4);
    expect(all).toContain("aws_service_discovery_service.otel_collector.arn");
    expect(all).toMatch(
      /description\s+=\s+"OTLP\/gRPC from application tasks"[\s\S]*?from_port\s+=\s+4317[\s\S]*?to_port\s+=\s+4317[\s\S]*?security_groups\s+=\s+local\.app_task_security_group_ids/,
    );
    expect(all).toMatch(
      /description\s+=\s+"OTLP\/HTTP from application tasks"[\s\S]*?from_port\s+=\s+4318[\s\S]*?to_port\s+=\s+4318[\s\S]*?security_groups\s+=\s+local\.app_task_security_group_ids/,
    );
    expect(all).not.toMatch(
      /from_port\s+=\s+4317[\s\S]{0,80}?to_port\s+=\s+4318/,
    );
    expect(all).toContain(
      'name = "OTEL_EXPORTER_OTLP_PROTOCOL", value = "http/protobuf"',
    );
    expect(all).toContain('name      = "OTEL_EXPORTER_OTLP_HEADERS"');
    expect(all).toContain(
      'valueFrom = "${aws_secretsmanager_secret.otel_otlp_auth.arn}:exporter_headers::"',
    );
    expect(all).toMatch(
      /resource "aws_ecs_service" "otel_collector"[\s\S]*?security_groups\s+=\s+\[aws_security_group\.ecs_otel\.id\]/,
    );
    expect(all).toMatch(
      /resource "aws_ecs_service" "otel_collector"[\s\S]*?health_check_grace_period_seconds\s+=\s+60/,
    );
    expect(all).toMatch(
      /variable "service_discovery_dns_ttl_seconds"[\s\S]*?condition\s+=\s+var\.service_discovery_dns_ttl_seconds >= 30 && var\.service_discovery_dns_ttl_seconds <= 300/,
    );
    expect(all).toMatch(
      /resource "aws_service_discovery_service" "otel_collector"[\s\S]*?ttl\s+=\s+var\.service_discovery_dns_ttl_seconds/,
    );
    expect(all).toMatch(
      /resource "aws_service_discovery_service" "control_plane"[\s\S]*?ttl\s+=\s+var\.service_discovery_dns_ttl_seconds/,
    );
    expect(all).not.toContain("ttl  = 10");
    expect(all).toMatch(
      /variable "otel_collector_desired_count"[\s\S]*?condition\s+=\s+var\.otel_collector_desired_count >= 2/,
    );
    expect(all).toMatch(
      /resource "aws_ecs_service" "otel_collector"[\s\S]*?desired_count\s+=\s+var\.otel_collector_desired_count/,
    );
    expect(all).toContain(
      'resource "aws_appautoscaling_target" "otel_collector"',
    );
    expect(all).toContain(
      "var.otel_collector_max_capacity >= var.otel_collector_min_capacity",
    );
    expect(all).toContain(
      'predefined_metric_type = "ECSServiceAverageCPUUtilization"',
    );
    expect(all).toContain(
      'predefined_metric_type = "ECSServiceAverageMemoryUtilization"',
    );
    expect(all).toContain(
      'resource "aws_cloudwatch_metric_alarm" "otel_collector_cpu_high"',
    );
    expect(all).toContain(
      'resource "aws_cloudwatch_metric_alarm" "otel_collector_memory_high"',
    );
    expect(readme).toContain("Rollback Runbook");
    expect(readme).toContain("aws ecs update-service");
    expect(readme).toContain("terraform apply rollback.tfplan");
  });

  it("keeps secrets out of Terraform source and state templates", () => {
    const all = secretCheckedFiles.map(readTerraform).join("\n");

    expect(all).not.toMatch(/password\s+=\s+"/i);
    expect(all).not.toMatch(/secret_string\s+=\s+"/i);
    expect(all).not.toMatch(/private_key\s+=\s+"/i);
    expect(readTerraform("env/demo.tfvars.example")).not.toMatch(
      /redis_auth_token\s+=\s+"/i,
    );
    expect(all).toMatch(/manage_master_user_password\s+=\s+true/);
  });

  it("ships a gated dashboard deploy workflow for public live rollout", () => {
    const workflow = readWorkflow("deploy-dashboard.yml");

    expect(workflow).toContain("workflow_dispatch");
    expect(workflow).toContain("workflow_run:");
    expect(workflow).toContain(
      "workflows: [Promote Clearance Dashboard Release]",
    );
    expect(workflow).toContain("resolve_deploy_context:");
    expect(workflow).toContain("Resolve deploy target environment");
    expect(workflow).toContain(
      "group: deploy-clearance-dashboard-${{ github.event_name == 'workflow_dispatch' && inputs.environment || 'release-promotion' }}-${{ github.event_name == 'workflow_dispatch' && inputs.rollback == true && 'rollback' || format('deploy-{0}', github.event.workflow_run.head_sha || github.sha) }}",
    );
    expect(workflow).toContain(
      "cancel-in-progress: ${{ !(github.event_name == 'workflow_dispatch' && inputs.rollback == true) }}",
    );
    expect(workflow).toContain("github.event.workflow_run.id");
    expect(workflow).not.toContain(
      "deploy-clearance-dashboard-${{ github.event_name == 'workflow_dispatch' && inputs.environment || " +
        "'release-event' }}",
    );
    expect(workflow).toContain(
      "name: aidenid-clearance-${{ needs.resolve_deploy_context.outputs.environment }}",
    );
    expect(workflow).not.toContain("inputs.environment || 'production'");
    expect(workflow).toContain(
      "Resolve release-manifest workflow_run dispatch",
    );
    expect(workflow).toContain("actions: read");
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain("default: false");
    expect(workflow).toContain(
      "Apply requires dashboard_hostname or canary_url",
    );
    expect(workflow).toContain("api.aidenid.com|swarm.aidenid.com");
    expect(workflow).toContain("dashboard_image");
    expect(workflow).toContain("ci_artifact_run_id");
    expect(workflow).toContain("omar_gate_run_id");
    expect(workflow).toContain("artifact_attestation_run_id");
    expect(workflow).toContain("attestation_contract_run_id");
    expect(workflow).toContain("scorecard_run_id");
    expect(workflow).toContain("release_manifest_run_id");
    expect(workflow).toContain(
      "workflow_dispatch deploy requires exact numeric ci_artifact_run_id",
    );
    expect(workflow).toContain(
      "workflow_dispatch deploy requires exact numeric release_manifest_run_id",
    );
    expect(workflow).toContain("AIDENID_ALLOWED_INGRESS_PREFIX_LIST_IDS_JSON");
    expect(workflow).toContain(
      "AIDENID_ALLOWED_INGRESS_CIDRS_EXCEPTION_TICKET",
    );
    expect(workflow).toContain("AIDENID_ALLOWED_INGRESS_CIDRS_EXPIRES_AT");
    expect(workflow).toContain("AIDENID_ALLOWED_EGRESS_PREFIX_LIST_IDS_JSON");
    expect(workflow).toContain("TF_VAR_allowed_ingress_prefix_list_ids");
    expect(workflow).toContain("TF_VAR_allowed_ingress_cidrs_exception_ticket");
    expect(workflow).toContain("TF_VAR_allowed_ingress_cidrs_expires_at");
    expect(workflow).toContain("TF_VAR_allowed_egress_prefix_list_ids");
    expect(workflow).toContain("TF_VAR_enable_nat_egress");
    expect(workflow).toContain("TF_VAR_enable_private_vpc_endpoints");
    expect(workflow).toContain("TF_VAR_service_discovery_dns_ttl_seconds");
    expect(workflow).toContain("TF_VAR_redis_final_snapshot_identifier_suffix");
    expect(workflow).toContain(
      "${DEPLOY_ENVIRONMENT}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}",
    );
    expect(workflow).toContain("no broader than /24 IPv4 or /64 IPv6");
    expect(workflow).toContain(
      "Demo raw CIDR ingress requires AIDENID_ALLOWED_INGRESS_CIDRS_EXCEPTION_TICKET",
    );
    expect(workflow).toContain(
      "Demo raw CIDR ingress exceptions must expire within 24 hours",
    );
    expect(workflow).toContain(
      "Public ALB ingress requires either ticketed demo raw CIDRs or managed allowed ingress prefix-list IDs",
    );
    expect(workflow).toContain(
      "Public ALB ingress must use exactly one source mode",
    );
    expect(workflow).toContain("must be a ${workflow} run");
    expect(workflow).toContain("must be completed/success");
    expect(workflow).toContain("latest-run discovery is forbidden");
    expect(workflow).toContain(
      "Verify CI/Omar/Scorecard/Attestation gates for every workflow_dispatch deploy SHA",
    );
    expect(workflow).toContain(
      "required_for_all_workflow_dispatch_apply: true",
    );
    expect(workflow).toContain(
      "required_for_all_workflow_dispatch_deploys: true",
    );
    expect(workflow).toContain("exact_run_ids_required: true");
    expect(workflow).toContain("enforced_for_non_production_apply: true");
    expect(workflow).toContain("workflow-dispatch-release-gates.json");
    expect(workflow).toContain(
      "workflow_dispatch deploys must be dispatched from refs/heads/main before Terraform plan/apply",
    );
    expect(workflow).toContain("expected_terraform_plan_sha256");
    expect(workflow).toContain("terraform_plan_approval_run_id");
    expect(workflow).toContain(
      "workflow_dispatch apply requires numeric terraform_plan_approval_run_id",
    );
    expect(workflow).toContain(
      "workflow_dispatch deploy requires exact numeric ci_artifact_run_id before deploy gate resolution",
    );
    expect(workflow).toContain(
      "dashboard-terraform-plan-approval-reviewed.json",
    );
    expect(workflow).toContain("dashboard-terraform-vars.sha256");
    expect(workflow).toContain("apply_rejects_expired_plan_approval");
    expect(workflow).toContain(
      "apply_binds_source_sha_environment_and_tfvars_digest",
    );
    expect(workflow).toContain(
      "apply=true requires expected_terraform_plan_sha256 from a reviewed apply=false plan-approval artifact",
    );
    expect(workflow).toContain("AIDENID_PROVENANCE_BUCKET");
    expect(workflow).toContain(
      "apply=true requires AIDENID_PROVENANCE_BUCKET so deploy can retrieve durable provenance before apply",
    );
    expect(workflow).toContain("AIDENID_DASHBOARD_IMAGE");
    expect(workflow).toContain("MANUAL_DASHBOARD_IMAGE");
    expect(workflow).toContain("RELEASE_EVENT_DASHBOARD_IMAGE");
    expect(workflow).toContain(
      "dashboard_image input is disabled for production",
    );
    expect(workflow).toContain(
      "Production deploys require a release manifest dashboard image or repository variable AIDENID_DASHBOARD_IMAGE",
    );
    expect(workflow).toContain("AIDENID_DASHBOARD_HOSTNAME");
    expect(workflow).toContain("AIDENID_CONTROL_PLANE_HOSTNAME");
    expect(workflow).toContain("AIDENID_VERIFIER_HOSTNAME");
    expect(workflow).toContain("Verify public ALB certificate SAN coverage");
    expect(workflow).toContain("phase4-public-alb-deploy-preflight");
    expect(workflow).toContain(
      "AIDENID_ALB_CERTIFICATE_ARN must point to the public SAN certificate before deploy apply",
    );
    expect(workflow).toContain("node scripts/terraform/verify-acm-san.mjs");
    expect(workflow).toContain("AIDENID_REDIS_AUTH_TOKEN");
    expect(workflow).toContain(
      "AIDENID_REDIS_AUTH_TOKEN must be 32-128 characters",
    );
    expect(workflow).toContain("Validate Redis AUTH token secret shape");
    expect(workflow).toContain("Validate OTel OTLP auth token secret shape");
    expect(workflow).toContain("Validate Cloudflare DNS token secret presence");
    expect(workflow).not.toContain("AIDENID_TERRAFORM_SECRET_TFVARS");
    expect(workflow).toContain("AIDENID_TF_STATE_KMS_KEY_ID");
    expect(workflow).toContain("repository@sha256:<64-hex-digest>");
    expect(workflow).toContain("@sha256:[0-9a-f]{64}");
    expect(workflow).toContain('validate_digest_image "Control-plane"');
    expect(workflow).toContain('validate_digest_image "Verifier"');
    expect(workflow).toContain('validate_digest_image "OTel collector"');
    expect(workflow).toContain("TF_VAR_dashboard_hostname");
    expect(workflow).toContain("TF_VAR_control_plane_hostname");
    expect(workflow).toContain("TF_VAR_verifier_hostname");
    expect(workflow).not.toContain(
      "TF_VAR_redis_auth_token=${AIDENID_REDIS_AUTH_TOKEN}",
    );
    expect(workflow).not.toContain("-var-file=");
    expect(workflow).toContain(
      "Verify CI/Omar/Scorecard/Attestation gates for every workflow_dispatch deploy SHA",
    );
    expect(workflow).toContain("runs-on: ubuntu-22.04");
    expect(workflow).toContain("Assert production environment review gate");
    expect(workflow).toContain("production_deploy_approval");
    expect(workflow).toContain(
      "needs.production_deploy_approval.outputs.approved == 'true'",
    );
    expect(workflow).toContain("AIDENID_EFFECTIVE_ENVIRONMENT");
    expect(workflow).toContain("AIDENID_EFFECTIVE_APPLY");
    expect(workflow).toContain(
      "Production apply reviewer assertion passed with bounded repo-admin fallback",
    );
    expect(workflow).toContain("AIDENID_DEPLOY_APPLY_APPROVED_UNTIL");
    expect(workflow).toContain(
      "workflow_dispatch production apply is disabled",
    );
    expect(workflow).toContain("refs/heads/main");
    expect(workflow).toContain("must equal current main");
    expect(workflow).toContain(
      'require_successful_workflow_run_id "CI" "${CI_ARTIFACT_RUN_ID}"',
    );
    expect(workflow).toContain("require_successful_workflow_jobs");
    expect(workflow).toContain("Required ${workflow} jobs verified");
    expect(workflow).toContain("sort_by(.createdAt) | reverse");
    expect(workflow).toContain(
      '\'["lint","test","security","build","sbom","quality"]\'',
    );
    expect(workflow).toContain(
      'require_successful_workflow_run_id "Omar Gate" "${OMAR_GATE_RUN_ID}"',
    );
    expect(workflow).toContain("'[\"gate\"]'");
    expect(workflow).toContain(
      'require_successful_workflow_run_id "Artifact Attestation" "${ARTIFACT_ATTESTATION_RUN_ID}"',
    );
    expect(workflow).toContain(
      'require_successful_workflow_run_id "Attestation Contract Check" "${ATTESTATION_CONTRACT_RUN_ID}"',
    );
    expect(workflow).toContain("'[\"attest artifact\"]'");
    expect(workflow).toContain(
      'require_successful_workflow_run_id "OpenSSF Scorecard" "${SCORECARD_RUN_ID}"',
    );
    expect(workflow).toContain("'[\"scorecard\"]'");
    expect(workflow).toContain(
      "Sync Redis AUTH token secret outside Terraform state",
    );
    expect(workflow).toContain("redis-auth-token-secret-sync-receipt.json");
    expect(workflow).toContain("credential_sync_status");
    expect(workflow).toContain("idempotent_credential_sync");
    expect(workflow).toContain("credential_value_matches_deploy_input");
    expect(workflow).toContain("terraform_state_secret_version: false");
    expect(workflow).toContain(
      "Verify Redis AUTH token rotation age before apply",
    );
    expect(workflow).toContain("redis-auth-token-rotation-gate.json");
    expect(workflow).toContain("rotation_epoch");
    expect(workflow).toContain("AIDENID_REDIS_AUTH_TOKEN_ROTATION_EPOCH");
    expect(workflow).toContain("TF_VAR_redis_auth_token_rotation_epoch");
    expect(workflow).toContain("redis-auth-token-preapply-state.json");
    expect(workflow).toContain("redis_auth_token_preapply_rotation_evidence");
    expect(workflow).toContain("terraform_rotation_epoch_plan_visibility");
    expect(workflow).toContain("rotation_age_gate");
    expect(workflow).toContain(
      "Block deploy completion unless live Redis AUTH is enabled and epoch-aligned",
    );
    expect(workflow).toContain("describe-replication-groups");
    expect(workflow).toContain("describe-cache-clusters");
    expect(workflow).toContain("redis-auth-token-postapply-availability.json");
    expect(workflow).toContain("redis_auth_token_postapply_availability_probe");
    expect(workflow).toContain("member_statuses: members");
    expect(workflow).toContain("cache_cluster_describe_required: true");
    expect(workflow).toContain("all_member_clusters_available");
    expect(workflow).toContain("ready_for_auth_token_modify");
    expect(workflow).toContain("required_before_auth_token_modify");
    expect(workflow).toContain("retry_on_invalid_cache_cluster_state");
    expect(workflow).toContain('wait_for_redis_available "before_auth_modify"');
    expect(workflow).toContain("InvalidCacheClusterState");
    expect(workflow).toContain("postapply_availability_artifact");
    expect(workflow).toContain("modify_attempts");
    expect(workflow).toContain("redis-auth-token-elasticache-readiness.json");
    expect(workflow).toContain("redis_auth_token_elasticache_readiness");
    expect(workflow).toContain("redis-auth-token-live-epoch-alignment.json");
    expect(workflow).toContain("redis_auth_token_live_epoch_alignment");
    expect(workflow).toContain("redis_auth_required: true");
    expect(workflow).toContain("expected_credential_update_strategy");
    expect(workflow).toContain("credential_last_modified_date");
    expect(workflow).toContain(
      "live_auth_last_modified_date_matches_rotation_epoch",
    );
    expect(workflow).toContain("live_auth_epoch_alignment_mode");
    expect(workflow).toContain("already_configured_noop_credential_sync");
    expect(workflow).toContain(
      "already_configured_noop_credential_sync_accepted",
    );
    expect(workflow).toContain("elasticache_modify_noop_response");
    expect(workflow).toContain("already_configured_live_state_validated");
    expect(workflow).toContain("live_auth_epoch_alignment_gate_passed");
    expect(workflow).not.toContain("already.*auth");
    expect(workflow).toContain(
      "auth_last_modified_not_older_than_secrets_manager_awscurrent",
    );
    expect(readTerraform("elasticache.tf")).toMatch(
      /UpdateStrategyDrift\s+=\s+"auth-token-update-strategy-not-ignored"/,
    );
    expect(readTerraform("elasticache.tf")).toMatch(
      /LiveEpochAlignment\s+=\s+"deploy-auth-token-last-modified-date-matches-rotation-epoch"/,
    );
    expect(readTerraform("elasticache.tf")).toMatch(
      /AuthTokenEnabledLiveGate\s+=\s+"deploy-dashboard-blocks-unless-AuthTokenEnabled-true"/,
    );
    expect(readTerraform("elasticache.tf")).toMatch(
      /AuthTokenStatePolicy\s+=\s+"auth-token-material-never-in-terraform-state"/,
    );
    expect(readTerraform("elasticache.tf")).not.toMatch(
      /ignore_changes\s*=\s*\[[\s\S]*?auth_token_update_strategy[\s\S]*?\]/,
    );
    expect(workflow).toContain(
      "Sync OTel OTLP auth secret outside Terraform state",
    );
    expect(workflow).toContain("otel-otlp-auth-secret-sync-receipt.json");
    expect(workflow).toContain("receiver_requires_bearer_token: true");
    expect(workflow).toContain(
      "Configure Redis AUTH token outside Terraform state",
    );
    expect(workflow).toContain("modify-replication-group");
    expect(workflow).toContain(
      "redis-auth-token-out-of-state-activation-receipt.json",
    );
    expect(workflow).toContain("terraform_state_plaintext_value: false");
    expect(workflow).toContain("credential_source");
    expect(workflow).toContain("cloudflare_proxied");
    expect(workflow).toContain(
      "AIDENID_DEPLOY_CLOUDFLARE_PROXIED: ${{ needs.resolve_deploy_context.outputs.cloudflare_proxied }}",
    );
    expect(workflow).toContain("--argjson proxied");
    expect(workflow).toContain(
      "curl_args=(-fsS --connect-timeout 5 --max-time 30 --retry 3 --retry-delay 2 --retry-all-errors)",
    );
    expect(workflow).toContain('curl "${curl_args[@]}"');
    expect(workflow).toContain("Cloudflare dashboard CNAME verified");
    expect(workflow).toContain("Upsert Cloudflare control-plane CNAME");
    expect(workflow).toContain("cloudflare-control-plane-cname-plan.json");
    expect(workflow).toContain("control_plane_cloudflare_cname_plan");
    expect(workflow).toContain("Cloudflare control-plane CNAME verified");
    expect(workflow).toContain("Upsert Cloudflare verifier CNAME");
    expect(workflow).toContain("cloudflare-verifier-cname-plan.json");
    expect(workflow).toContain("verifier_cloudflare_cname_plan");
    expect(workflow).toContain("Cloudflare verifier CNAME verified");
    expect(workflow).not.toContain("docker build");
    expect(workflow).not.toContain("docker push");
    const deployArtifactBindingIndex = workflow.indexOf(
      "Verify deploy artifact, SBOM, and image binding",
    );
    const dashboardImageAttestationIndex = workflow.indexOf(
      "Verify dashboard image signing attestation",
    );
    const ecrLoginIndex = workflow.indexOf("aws ecr get-login-password");
    const ecrConfigPermissionIndex = workflow.indexOf(
      'chmod 0644 "${cosign_docker_config}/config.json"',
    );
    expect(dashboardImageAttestationIndex).toBeGreaterThan(
      deployArtifactBindingIndex,
    );
    expect(ecrLoginIndex).toBeGreaterThan(dashboardImageAttestationIndex);
    expect(ecrConfigPermissionIndex).toBeGreaterThan(ecrLoginIndex);
    expect(workflow).toContain('terraform -chdir="${TERRAFORM_DIR}" plan');
    expect(workflow).toContain("Terraform policy security gate");
    expect(workflow).toContain("node scripts/security-scan.mjs iac");
    expect(workflow).toContain("plan -lock-timeout=5m");
    expect(workflow).toContain("apply -lock-timeout=5m");
    expect(workflow).toContain("dashboard-terraform-plan.txt");
    expect(workflow).toContain("dashboard-terraform-plan-approval.json");
    expect(workflow).toContain("dashboard-terraform-plan-approval.sha256");
    expect(workflow).toContain("write-dashboard-terraform-plan-approval.mjs");
    expect(workflow).toContain("dashboard-preapply-readiness.json");
    expect(workflow).toContain("write-dashboard-preapply-readiness.mjs");
    expect(workflow).toContain("deploy-output/dashboard-ecs-rollback.sh");
    expect(workflow).toContain("deploy-output/ecs-preapply/*.json");
    expect(workflow).toContain("describe-task-definition");
    expect(workflow).toContain("taskDefinition.status");
    expect(workflow).toContain(
      'if [ "\\${task_definition_status}" = "ACTIVE" ]; then',
    );
    expect(workflow).toContain("skipping update-service");
    expect(workflow).toContain(
      "relying on ECS circuit breaker/service stability evidence",
    );
    expect(workflow).toContain("bash deploy-output/dashboard-ecs-rollback.sh");
    expect(workflow).toContain("cloudflare-dashboard-cname-plan.json");
    expect(workflow).toContain("cloudflare-control-plane-cname-plan.json");
    expect(workflow).toContain(
      "Require post-deploy automated health canary success",
    );
    expect(workflow).toContain("dashboard-post-deploy-health-canary-gate.json");
    expect(workflow).toContain(
      'cloudflare_proxied_json="${CLOUDFLARE_PROXIED}"',
    );
    expect(workflow).toContain(
      'dashboard_hostname="${DASHBOARD_HOSTNAME:-${AIDENID_DASHBOARD_HOSTNAME:-}}"',
    );
    expect(workflow).toContain("required_for_apply_success: true");
    expect(workflow).toContain("timeout-minutes: 8");
    expect(workflow).toContain('gh run download "${CI_RUN_ID}"');
    expect(workflow).toContain("AIDENID_RELEASE_EVENT_OMAR_RUN_ID");
    expect(workflow).toContain("AIDENID_RELEASE_EVENT_ATTESTATION_RUN_ID");
    expect(workflow).toContain(
      'CI_RUN_ID="${CI_RUN_ID:-${AIDENID_RELEASE_EVENT_CI_RUN_ID:-}}"',
    );
    expect(workflow).toContain(
      'RELEASE_MANIFEST_RUN_ID="${RELEASE_MANIFEST_RUN_ID:-${AIDENID_RELEASE_EVENT_RELEASE_RUN_ID:-}}"',
    );
    expect(workflow).toContain(
      "apply=true deploy requires numeric Artifact Attestation run id from workflow_dispatch input or release manifest",
    );
    expect(workflow).toContain("sha256sum -c aidenid-clearance-build.sha256");
    expect(workflow).toContain("sha256sum -c ci-artifact-manifest.sha256");
    expect(workflow).toContain(
      "Verify deploy artifact, SBOM, and image binding",
    );
    expect(workflow).toContain("node scripts/verify-ci-sbom.mjs");
    expect(workflow).toContain("gh attestation verify");
    expect(workflow).toContain('dashboard_registry="${DASHBOARD_IMAGE%%/*}"');
    expect(workflow).toContain("build-and-push-images.yml@refs/heads/main");
    expect(workflow).toContain(
      'aws ecr get-login-password --region "${ecr_region}"',
    );
    expect(workflow).toContain(
      'docker --config "${cosign_docker_config}" login --username AWS --password-stdin "${dashboard_registry}"',
    );
    expect(workflow).toContain('chmod 0755 "${cosign_docker_config}"');
    expect(workflow).toContain(
      'chmod 0644 "${cosign_docker_config}/config.json"',
    );
    expect(workflow).toContain(
      '"${cosign_docker_config}:/tmp/cosign-docker-config:ro"',
    );
    expect(workflow).toContain("dashboard-provenance");
    expect(workflow).toContain("verify_downloaded_provenance_sha256()");
    expect(workflow).toContain(
      'checksum_basename="$(basename "${checksum_path}")"',
    );
    expect(workflow).toContain(
      "verify_downloaded_provenance_sha256 aidenid-clearance-provenance.sha256 aidenid-clearance-provenance.json",
    );
    expect(workflow).toContain(
      "verify_downloaded_provenance_sha256 aidenid-clearance-provenance-release-binding.sha256 aidenid-clearance-provenance-release-binding.json",
    );
    expect(workflow).toContain(
      "verify_downloaded_provenance_sha256 aidenid-clearance-provenance-durable-receipt.sha256 aidenid-clearance-provenance-durable-receipt.json",
    );
    expect(workflow).toContain("native_attestation_status");
    expect(workflow).toContain("provenance_storage_uri");
    expect(workflow).toContain("dashboard_image_release_binding");
    expect(workflow).toContain("dashboard_release_manifest");
    expect(workflow).toContain(
      "dashboard-release-manifest-${DEPLOY_ENVIRONMENT}-${DEPLOY_SHA}",
    );
    expect(workflow).toContain("image_subject.dashboard_image_digest");
    expect(workflow).toContain("image_subject.ci_artifact_sha256");
    expect(workflow).toContain("github_artifact_id");
    expect(workflow).toContain("github_artifact_archive_digest");
    expect(workflow).toContain("immutable_promotion.artifact_id");
    expect(workflow).toContain("requires_immutable_artifact_tuple == true");
    expect(workflow).toContain(".gates.ci.artifact.archive_sha256");
    expect(workflow).toContain("service_images.control_plane.image");
    expect(workflow).toContain("service_images.verifier.image");
    expect(workflow).toContain("service_images.otel_collector.image");
    expect(workflow).toContain("requires_release_manifest_for_all_apply");
    expect(workflow).toContain("requires_ci_artifact_binding == true");
    expect(workflow).toContain("release_manifest_sha256");
    expect(workflow).toContain("dashboard-image-release-binding.sha256");
    expect(workflow).toContain("release_binding_sha256");
    expect(workflow).toContain("ci_sbom_sha256");
    expect(workflow).toContain("Require post-rollback verification evidence");
    expect(workflow).toContain("required_for_rollback_success");
    expect(workflow).toContain(
      "diff -u ci-artifact-manifest.txt ci-artifact-manifest.actual",
    );
    expect(workflow).toContain("AIDENID_CONTROL_PLANE_HOSTNAME");
    expect(workflow).toContain("AIDENID_VERIFIER_HOSTNAME");
    expect(workflow).toContain(
      'canary_args=("${target}" "--site-id" "${dashboard_site_id}")',
    );
    expect(workflow).toContain(
      'dashboard_operator_secret_name="${AIDENID_CLEARANCE_PROJECT}-${DEPLOY_ENVIRONMENT}/dashboard/operator-token"',
    );
    expect(workflow).toContain("aws secretsmanager get-secret-value");
    expect(workflow).toContain(
      'echo "::add-mask::${dashboard_operator_token}"',
    );
    expect(workflow).toContain(
      'verifier_operator_secret_name="${AIDENID_CLEARANCE_PROJECT}-${DEPLOY_ENVIRONMENT}/control-plane/operator-tokens"',
    );
    expect(workflow).toContain(
      'select(.name == "AIDENID_CONTROL_PLANE_API_KEY")',
    );
    expect(workflow).toContain(
      'dashboard_token_env_name="AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN"',
    );
    expect(workflow).toContain(
      'control_plane_key_env_name="AIDENID_CONTROL_PLANE_API_KEY"',
    );
    expect(workflow).toContain(
      'printf -v "${control_plane_key_env_name}" \'%s\' "${control_plane_api_key}"',
    );
    expect(workflow).toContain('echo "::add-mask::${control_plane_api_key}"');
    expect(workflow).toContain('select(.name == "AIDENID_DASHBOARD_SITE_ID")');
    expect(workflow).toContain(
      'check_public_endpoint "control-plane health" "https://${AIDENID_CONTROL_PLANE_HOSTNAME}/healthz"',
    );
    expect(workflow).toContain(
      'check_public_endpoint "verifier health" "https://${AIDENID_VERIFIER_HOSTNAME}/healthz"',
    );
    expect(workflow).toContain(
      'canary_args+=("--emit-probe" "--control-plane-url" "https://${AIDENID_CONTROL_PLANE_HOSTNAME}")',
    );
    expect(workflow).toContain(
      'timeout 25s node "${canary_src}/scripts/check-dashboard-live.mjs" "${canary_args[@]}"',
    );
    expect(workflow).not.toContain("pnpm install --frozen-lockfile");
    expect(workflow).not.toContain("--allow-sample");
    const dashboardCanary = readRepo("scripts/check-dashboard-live.mjs");
    expect(dashboardCanary).toContain("status.fallbackDataEnabled === true");
    expect(dashboardCanary).toContain(
      "status.controlPlaneStreamConfigured !== true",
    );
    expect(dashboardCanary).toContain(
      'streamDataSource !== "live" && !allowSample',
    );
    expect(dashboardCanary).toContain("event:\\s*stream_error");
    expect(dashboardCanary).toContain("decision_stream_unavailable");
    expect(dashboardCanary).toContain("live_control_plane_required");
    expect(dashboardCanary).toContain("emitSyntheticDecision");
    expect(dashboardCanary).toContain("observeContinuousProbe");
    expect(dashboardCanary).toContain('new URL("api/decisions/stream", base)');
    expect(dashboardCanary).toContain("observedProbe");
    expect(dashboardCanary).toContain("Last-Event-ID");
    expect(dashboardCanary).toContain("verifyAnonymousStreamBoundary");
    expect(dashboardCanary).toContain("operator_auth_required");
    expect(dashboardCanary).toContain("anonymousStreamDenied");
    expect(dashboardCanary).toContain("authenticatedStreamObserved");
    expect(dashboardCanary).toContain(
      "AIDENID_DASHBOARD_OPERATOR_REQUEST_TOKEN",
    );
    expect(dashboardCanary).toContain("site_id: siteId");
    expect(workflow).toContain("canary_target");
    expect(workflow).toContain("canary_verdict");
    expect(workflow).toContain("Verify deploy summary canary verdict");
    expect(workflow).toContain("verify-dashboard-deploy-summary.mjs");
    expect(workflow).toContain("dashboard-deploy-canary-verdict.json");
    expect(workflow).toContain(
      "Run rollback readiness after failed apply or canary",
    );
    expect(workflow).toContain("aws ecs wait services-stable");
    expect(workflow).toContain("describe-task-definition");
    expect(workflow).toContain("skipping update-service");
    expect(workflow).toContain("dashboard-rollback-readiness.json");
    expect(workflow).toContain(
      "Require recent rollback drill evidence before apply",
    );
    expect(workflow).toContain(
      "Require recent rollback drill evidence before rollback",
    );
    expect(workflow).toContain("verify-dashboard-rollback-drill.mjs");
    expect(workflow).toContain(
      "dashboard-rollback-drills/${DEPLOY_ENVIRONMENT}/latest.json",
    );
    expect(workflow).toContain("dashboard-rollback-drill-evidence.json");
    expect(workflow).toContain("rollback_artifact_run_id");
    expect(workflow).toContain("rollback_incident_ticket");
    expect(workflow).toContain(
      "AIDENID_DASHBOARD_ROLLBACK_ARTIFACT_MAX_AGE_HOURS",
    );
    expect(workflow).toContain("production_rollback_approval");
    expect(workflow).toContain("aidenid-clearance-production-rollback");
    expect(workflow).toContain(
      "inputs.environment == 'production' && 'aidenid-clearance-production-rollback'",
    );
    expect(workflow).toContain("rollback-specific protected approval");
    expect(workflow).toContain(
      "production rollback-specific approval requires rollback_incident_ticket before any rollback artifact download or script execution",
    );
    expect(workflow).toContain("execute saved dashboard rollback");
    expect(workflow).toContain("dashboard-manual-rollback-summary");
    expect(workflow).toContain("dashboard-manual-rollback-verification");
    expect(workflow).toContain("rollback-current-environment-state.json");
    expect(workflow).toContain("matching_service_image_lineage_verified");
    expect(workflow).toContain("current_environment_state_parity_verified");
    expect(workflow).toContain("services_stable: true");
    expect(workflow).toContain("post-rollback canary");

    for (const [, ref] of workflow.matchAll(/uses:\s+[^\s@]+@([^\s]+)/g)) {
      expect(ref).toMatch(/^[0-9a-f]{40}$/);
    }
  });
});
