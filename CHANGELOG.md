# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-04-28

### Added

- **SSM Lambda path** - Added `/{env}/lambda/*` to SSM parameter permissions for Lambda exports

---

## [1.2.0] - 2026-04-27

### Added

- **ECR permissions** - Full Elastic Container Registry support for Lambda container deployments
- **Lambda permissions** - Complete Lambda function lifecycle management
- **CloudWatch Logs permissions** - Lambda log group management

### Changed

- **Split IAM policy into 3 policies** - AWS has a 6,144 character limit per managed policy. The single `TerraformDeploymentPolicy` has been split into:
  - `TerraformDeployment-Core-{env}` - S3, KMS, SSM, STS
  - `TerraformDeployment-IAM-{env}` - IAM roles, policies, OIDC, CloudTrail
  - `TerraformDeployment-Lambda-{env}` - ECR, Lambda, CloudWatch Logs

### ECR Permissions

| Statement | Description |
|-----------|-------------|
| ECRRepositoryManagement | Create, delete, describe repos, policies, lifecycle, scanning |
| ECRImageOperations | Push, pull, delete images, layer operations |
| ECRGetAuthorizationToken | Docker login authentication |
| ECRDescribeOperations | Describe registry |

### Lambda Permissions

| Statement | Description |
|-----------|-------------|
| LambdaFunctionManagement | Create, delete, update functions, versions, tags |
| LambdaAliasManagement | Manage function aliases |
| LambdaEventSourceMapping | SQS, Kinesis, DynamoDB triggers |
| LambdaPermissions | API Gateway, S3 trigger permissions |
| LambdaConcurrency | Reserved and provisioned concurrency |
| IAMLambdaRoleManagement | Create/manage Lambda execution roles |
| IAMPassRoleToLambda | Pass roles to Lambda service |
| CloudWatchLogsManagement | Lambda log group lifecycle |

### Resource Patterns

All resources scoped to environment:
- ECR: `*-{env}`, `*-{env}-*`
- Lambda: `*-{env}`, `*-{env}-*`
- IAM Roles: `*-{env}-lambda`, `lambda-*-{env}`
- Log Groups: `/aws/lambda/*-{env}`, `/aws/lambda/*-{env}-*`

---

## [1.1.0] - 2026-04-25

### Added

- **Data Lake S3 bucket permissions** - IAM policy now supports deploying `aws-datalake-layers` infrastructure

### Changed

- **S3StateBucketList** - Added `datalake-*-{company}-{env}-*` ARN pattern
- **S3BucketMetadataRead** - Added datalake bucket ARN for plan/refresh operations
- **S3StateObjects** - Added datalake bucket ARN for object-level operations
- **S3BucketCreate** - Added datalake bucket ARN for bucket creation
- **S3BucketManage** - Added datalake bucket ARN for bucket management (versioning, encryption, lifecycle)
- **KMSCreateKey** - Added `Project=datalake` tag condition for creating KMS keys
- **KMSAliasWrite** - Added `datalake-*` alias pattern
- **KMSAliasTargetKey** - Added `Project=datalake` tag condition
- **KMSManageTaggedKeys** - Added `Project=datalake` tag condition for key management
- **KMSStateUsage** - Added `Project=datalake` tag condition for encryption/decryption
- **SSMParameterRead** - Added `/{env}/datalake/*` parameter path
- **SSMParameterWrite** - Added `/{env}/datalake/*` parameter path

### Supported Datalake Buckets

The IAM policy now allows managing these bucket patterns:

| Layer | Bucket Pattern |
|-------|----------------|
| Raw | `datalake-raw-{company}-{env}-{account}` |
| Staging | `datalake-staging-{company}-{env}-{account}` |
| Business | `datalake-business-{company}-{env}-{account}` |

---

## [1.0.0] - 2026-04-24

### Initial Release

This repository was created from the [aws-bootstrap-tfstate-oidc-template](https://github.com/vigalcontec/aws-bootstrap-tfstate-oidc-template) v0.3.0 following the README deployment guide.

### Configured

- **Organisation settings** (`live/common.hcl`):
  - `company_name`: vigalcontec
  - `github_org`: vigalcontec
  - `github_repo`: * (all repositories)
  - `aws_region`: eu-west-1

- **Environment configurations**:
  - `live/dev/bootstrap/terragrunt.hcl` - Dev environment with remote state enabled
  - `live/qa/bootstrap/terragrunt.hcl` - QA environment with remote state enabled
  - `live/prod/bootstrap/terragrunt.hcl` - Prod environment with remote state enabled

- **CI/CD Workflows**:
  - `terraform-deploy.yml` - Automated deployment with environment detection
  - `pr-checks.yml` - PR quality checks, cost estimation, compliance verification
  - `drift-detection.yml` - Daily infrastructure drift detection

### Infrastructure Deployed

Per environment (dev/qa/prod):

| Resource | Name Pattern | Purpose |
|----------|--------------|---------|
| OIDC Provider | `token.actions.githubusercontent.com` | Keyless GitHub Actions authentication |
| IAM Role | `github-actions-terraform-{env}` | CI/CD role assumed by workflows |
| IAM Policy | `TerraformDeploymentPolicy-{env}` | ARN-scoped permissions |
| S3 Bucket | `tfstate-vigalcontec-{env}-{account-id}` | Terraform state storage |
| S3 Logs Bucket | `tfstate-vigalcontec-{env}-{account-id}-logs` | Access logging |
| KMS Key | `terraform-state-{env}` | State encryption |
| SSM Parameters | `/{env}/bootstrap/*` | Cross-project exports |

### Security

- ✅ GitHub OIDC federation (no long-lived credentials)
- ✅ KMS encryption with automatic key rotation
- ✅ S3 versioning and lifecycle policies
- ✅ ARN-based environment isolation
- ✅ TLS 1.2+ enforced on S3 buckets
- ✅ Public access blocked on all buckets