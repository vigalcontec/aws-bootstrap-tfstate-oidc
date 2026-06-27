# ================================================
# Terraform Deployment IAM Policies
#
# Split into multiple policies to avoid AWS 6,144 character limit.
#
# Security model:
#   1. OIDC trust policy — only GitHub Actions from allowed repos/branches can assume this role.
#   2. ARN-based scope   — all resource-level permissions are scoped to environment-specific
#                          ARN patterns. resources = ["*"] is used ONLY where AWS does not
#                          support resource-level permissions (list operations, kms:CreateKey).
#   3. KMS condition     — kms:CreateKey requires aws:RequestTag/Project = "bootstrap".
#                          KMS management actions require aws:ResourceTag/Project = "bootstrap".
#
# Policies:
#   - Core: S3, KMS, SSM, STS (state management and core infrastructure)
#   - IAM: IAM roles, policies, OIDC, CloudTrail
#   - Lambda: ECR, Lambda, CloudWatch Logs
#   - StepFunctions: Step Functions, EventBridge
# ================================================

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 1: Core Infrastructure (S3, KMS, SSM, STS)
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_core" {

  # ── S3: List the state bucket ───────────────────────────────────────────────
  statement {
    sid     = "S3StateBucketList"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    resources = [
      "arn:aws:s3:::tfstate-${var.company_name}-${var.environment}-*",
      "arn:aws:s3:::datalake-*-${var.company_name}-${var.environment}-*",
    ]
  }

  # ── S3: Read bucket metadata (plan refresh, import, state reads) ────────────
  statement {
    sid    = "S3BucketMetadataRead"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicy",
      "s3:GetBucketTagging",
      "s3:GetLifecycleConfiguration",
      "s3:GetBucketAcl",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetBucketLogging",
      "s3:GetBucketOwnershipControls",
      "s3:GetBucketCors",
      "s3:GetBucketWebsite",
      "s3:GetAccelerateConfiguration",
      "s3:GetBucketRequestPayment",
      "s3:GetReplicationConfiguration",
      "s3:PutEncryptionConfiguration",
      "s3:ListBucketVersions",
      "s3:PutBucketLogging",
      "s3:PutBucketOwnershipControls",
    ]
    resources = [
      "arn:aws:s3:::tfstate-${var.company_name}-${var.environment}-*",
      "arn:aws:s3:::cloudtrail-${var.company_name}-${var.environment}-*",
      "arn:aws:s3:::datalake-*-${var.company_name}-${var.environment}-*",
    ]
  }

  # ── S3: ListAllMyBuckets — no resource-level support, must be * ─────────────
  statement {
    sid       = "S3ListAllBuckets"
    effect    = "Allow"
    actions   = ["s3:ListAllMyBuckets"]
    resources = ["*"]
  }

  # ── S3: State object read/write ─────────────────────────────────────────────
  statement {
    sid    = "S3StateObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:GetObjectVersion",
      "s3:DeleteObjectVersion",
    ]
    resources = [
      "arn:aws:s3:::tfstate-${var.company_name}-${var.environment}-*/*",
      "arn:aws:s3:::datalake-*-${var.company_name}-${var.environment}-*/*",
    ]
  }

  # ── S3: Create and manage buckets ───────────────────────────────────────────
  statement {
    sid    = "S3BucketManage"
    effect = "Allow"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:PutBucketTagging",
      "s3:PutBucketVersioning",
      "s3:PutEncryptionConfiguration",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
      "s3:PutLifecycleConfiguration",
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutBucketOwnershipControls",
      "s3:PutBucketLogging",
      "s3:PutBucketAcl",
      "s3:PutBucketNotification",
      "s3:GetBucketNotification",
    ]
    resources = [
      "arn:aws:s3:::tfstate-${var.company_name}-${var.environment}-*",
      "arn:aws:s3:::cloudtrail-${var.company_name}-${var.environment}-*",
      "arn:aws:s3:::datalake-*-${var.company_name}-${var.environment}-*",
    ]
  }

  # ── KMS: CreateKey — enforce Project tag ────────────────────────────────────
  statement {
    sid       = "KMSCreateKey"
    effect    = "Allow"
    actions   = ["kms:CreateKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = ["bootstrap", "datalake"]
    }
  }

  # ── KMS: Alias management ───────────────────────────────────────────────────
  statement {
    sid    = "KMSAliasWrite"
    effect = "Allow"
    actions = [
      "kms:CreateAlias",
      "kms:DeleteAlias",
    ]
    resources = [
      "arn:aws:kms:*:${local.account_id}:alias/${var.company_name}-*",
      "arn:aws:kms:*:${local.account_id}:alias/datalake-*",
    ]
  }

  statement {
    sid       = "KMSAliasTargetKey"
    effect    = "Allow"
    actions   = ["kms:CreateAlias"]
    resources = ["arn:aws:kms:*:${local.account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = ["bootstrap", "datalake"]
    }
  }

  statement {
    sid       = "KMSListAliases"
    effect    = "Allow"
    actions   = ["kms:ListAliases"]
    resources = ["*"]
  }

  # ── KMS: Manage tagged keys ─────────────────────────────────────────────────
  statement {
    sid    = "KMSManageTaggedKeys"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateKeyDescription",
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:Encrypt",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = ["bootstrap", "datalake"]
    }
  }

  # ── STS & SSM ───────────────────────────────────────────────────────────────
  statement {
    sid       = "STSGetCallerIdentity"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }

  statement {
    sid    = "SSMParameterAccess"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:PutParameter",
      "ssm:DeleteParameter",
      "ssm:AddTagsToResource",
      "ssm:RemoveTagsFromResource",
      "ssm:ListTagsForResource",
    ]
    resources = [
      # General pattern: /{env}/{project}/{service}/* - works for all services
      "arn:aws:ssm:*:${local.account_id}:parameter/${var.environment}/*",
    ]
  }

  statement {
    sid       = "SSMDescribeParameters"
    effect    = "Allow"
    actions   = ["ssm:DescribeParameters"]
    resources = ["*"]
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 2: IAM & CloudTrail
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_iam" {

  # ── IAM: List operations ────────────────────────────────────────────────────
  statement {
    sid    = "IAMListOperations"
    effect = "Allow"
    actions = [
      "iam:ListRoles",
      "iam:ListPolicies",
      "iam:ListOpenIDConnectProviders",
    ]
    resources = ["*"]
  }

  # ── IAM: OIDC provider ──────────────────────────────────────────────────────
  statement {
    sid    = "IAMOIDCProviderManagement"
    effect = "Allow"
    actions = [
      "iam:CreateOpenIDConnectProvider",
      "iam:DeleteOpenIDConnectProvider",
      "iam:GetOpenIDConnectProvider",
      "iam:TagOpenIDConnectProvider",
      "iam:UntagOpenIDConnectProvider",
      "iam:UpdateOpenIDConnectProviderThumbprint",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com",
    ]
  }

  # ── IAM: Bootstrap role management ──────────────────────────────────────────
  statement {
    sid    = "IAMRoleManagement"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/github-actions-terraform-${var.environment}",
    ]
  }

  # ── IAM: Policy management ──────────────────────────────────────────────────
  statement {
    sid    = "IAMPolicyManagement"
    effect = "Allow"
    actions = [
      "iam:CreatePolicy",
      "iam:DeletePolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:TagPolicy",
      "iam:UntagPolicy",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:policy/TerraformDeployment-*-${var.environment}",
    ]
  }

  # ── IAM: PassRole for bootstrap ─────────────────────────────────────────────
  statement {
    sid       = "IAMPassRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/github-actions-terraform-${var.environment}"]
  }

  # ── IAM: Lambda execution roles ─────────────────────────────────────────────
  statement {
    sid    = "IAMLambdaRoleManagement"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-lambda",
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-lambda-*",
      "arn:aws:iam::${local.account_id}:role/lambda-*-${var.environment}",
      "arn:aws:iam::${local.account_id}:role/lambda-*-${var.environment}-*",
    ]
  }

  # ── IAM: Step Function execution roles ────────────────────────────────────────
  statement {
    sid    = "IAMStepFunctionRoleManagement"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-sfn",
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-sfn-*",
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-eventbridge",
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-eventbridge-*",
    ]
  }

  # ── IAM: PassRole for Step Functions ──────────────────────────────────────────
  statement {
    sid     = "IAMPassRoleToStepFunctions"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-sfn",
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-sfn-*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["states.amazonaws.com"]
    }
  }

  # ── IAM: PassRole for EventBridge ─────────────────────────────────────────────
  statement {
    sid     = "IAMPassRoleToEventBridge"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-eventbridge",
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-eventbridge-*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["events.amazonaws.com"]
    }
  }

  # ── IAM: PassRole for Lambda ────────────────────────────────────────────────
  statement {
    sid     = "IAMPassRoleToLambda"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-lambda",
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-lambda-*",
      "arn:aws:iam::${local.account_id}:role/lambda-*-${var.environment}",
      "arn:aws:iam::${local.account_id}:role/lambda-*-${var.environment}-*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  # ── CloudTrail ──────────────────────────────────────────────────────────────
  statement {
    sid    = "CloudTrailListOperations"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:ListTrails",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudTrailManagement"
    effect = "Allow"
    actions = [
      "cloudtrail:CreateTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:DeleteTrail",
      "cloudtrail:GetTrail",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:StartLogging",
      "cloudtrail:StopLogging",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:PutInsightSelectors",
      "cloudtrail:GetInsightSelectors",
      "cloudtrail:AddTags",
      "cloudtrail:RemoveTags",
      "cloudtrail:ListTags",
    ]
    resources = [
      "arn:aws:cloudtrail:*:${local.account_id}:trail/centralized-audit-trail-${var.environment}",
    ]
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 3: Lambda & ECR
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_lambda" {

  # ── ECR: Repository management ──────────────────────────────────────────────
  statement {
    sid    = "ECRRepositoryManagement"
    effect = "Allow"
    actions = [
      "ecr:CreateRepository",
      "ecr:DeleteRepository",
      "ecr:DescribeRepositories",
      "ecr:TagResource",
      "ecr:UntagResource",
      "ecr:ListTagsForResource",
      "ecr:SetRepositoryPolicy",
      "ecr:GetRepositoryPolicy",
      "ecr:DeleteRepositoryPolicy",
      "ecr:PutLifecyclePolicy",
      "ecr:GetLifecyclePolicy",
      "ecr:DeleteLifecyclePolicy",
      "ecr:PutImageScanningConfiguration",
      "ecr:PutImageTagMutability",
    ]
    resources = [
      "arn:aws:ecr:*:${local.account_id}:repository/*-${var.environment}",
      "arn:aws:ecr:*:${local.account_id}:repository/*-${var.environment}-*",
    ]
  }

  # ── ECR: Image operations ───────────────────────────────────────────────────
  statement {
    sid    = "ECRImageOperations"
    effect = "Allow"
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:BatchDeleteImage",
      "ecr:DescribeImages",
      "ecr:ListImages",
    ]
    resources = [
      "arn:aws:ecr:*:${local.account_id}:repository/*-${var.environment}",
      "arn:aws:ecr:*:${local.account_id}:repository/*-${var.environment}-*",
    ]
  }

  # ── ECR: Global operations ──────────────────────────────────────────────────
  statement {
    sid    = "ECRGlobalOperations"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:DescribeRegistry",
      "ecr:DescribePullThroughCacheRules",
    ]
    resources = ["*"]
  }

  # ── Lambda: Function management ─────────────────────────────────────────────
  statement {
    sid    = "LambdaFunctionManagement"
    effect = "Allow"
    actions = [
      "lambda:CreateFunction",
      "lambda:DeleteFunction",
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:PublishVersion",
      "lambda:ListVersionsByFunction",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:ListTags",
      "lambda:CreateAlias",
      "lambda:DeleteAlias",
      "lambda:GetAlias",
      "lambda:UpdateAlias",
      "lambda:ListAliases",
      "lambda:AddPermission",
      "lambda:RemovePermission",
      "lambda:GetPolicy",
      "lambda:PutFunctionConcurrency",
      "lambda:DeleteFunctionConcurrency",
      "lambda:GetFunctionConcurrency",
    ]
    resources = [
      "arn:aws:lambda:*:${local.account_id}:function:*-${var.environment}",
      "arn:aws:lambda:*:${local.account_id}:function:*-${var.environment}:*",
      "arn:aws:lambda:*:${local.account_id}:function:*-${var.environment}-*",
      "arn:aws:lambda:*:${local.account_id}:function:*-${var.environment}-*:*",
    ]
  }

  # ── Lambda: Global operations ───────────────────────────────────────────────
  statement {
    sid    = "LambdaGlobalOperations"
    effect = "Allow"
    actions = [
      "lambda:ListFunctions",
      "lambda:CreateEventSourceMapping",
      "lambda:DeleteEventSourceMapping",
      "lambda:GetEventSourceMapping",
      "lambda:UpdateEventSourceMapping",
      "lambda:ListEventSourceMappings",
    ]
    resources = ["*"]
  }

  # ── CloudWatch Logs ─────────────────────────────────────────────────────────
  statement {
    sid    = "CloudWatchLogsManagement"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:TagLogGroup",
      "logs:UntagLogGroup",
      "logs:ListTagsLogGroup",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:ListTagsForResource",
    ]
    resources = [
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/lambda/*-${var.environment}",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/lambda/*-${var.environment}:*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/lambda/*-${var.environment}-*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/lambda/*-${var.environment}-*:*",
    ]
  }

  statement {
    sid       = "CloudWatchLogsDescribe"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 4: Step Functions & EventBridge
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_stepfunctions" {

  # ── Step Functions: State machine management ──────────────────────────────────
  statement {
    sid    = "StepFunctionsManagement"
    effect = "Allow"
    actions = [
      "states:CreateStateMachine",
      "states:DeleteStateMachine",
      "states:DescribeStateMachine",
      "states:UpdateStateMachine",
      "states:ListStateMachines",
      "states:ListStateMachineVersions",
      "states:PublishStateMachineVersion",
      "states:DeleteStateMachineVersion",
      "states:DescribeStateMachineForExecution",
      "states:TagResource",
      "states:UntagResource",
      "states:ListTagsForResource",
    ]
    resources = [
      "arn:aws:states:*:${local.account_id}:stateMachine:*-${var.environment}",
      "arn:aws:states:*:${local.account_id}:stateMachine:*-${var.environment}-*",
    ]
  }

  # ── Step Functions: Execution operations ──────────────────────────────────────
  statement {
    sid    = "StepFunctionsExecutions"
    effect = "Allow"
    actions = [
      "states:StartExecution",
      "states:StopExecution",
      "states:DescribeExecution",
      "states:ListExecutions",
      "states:GetExecutionHistory",
    ]
    resources = [
      "arn:aws:states:*:${local.account_id}:stateMachine:*-${var.environment}",
      "arn:aws:states:*:${local.account_id}:stateMachine:*-${var.environment}-*",
      "arn:aws:states:*:${local.account_id}:execution:*-${var.environment}:*",
      "arn:aws:states:*:${local.account_id}:execution:*-${var.environment}-*:*",
    ]
  }

  # ── Step Functions: Global operations ──────────────────────────────────────────
  statement {
    sid    = "StepFunctionsGlobalOperations"
    effect = "Allow"
    actions = [
      "states:ListStateMachines",
      "states:ValidateStateMachineDefinition",
    ]
    resources = ["*"]
  }

  # ── EventBridge: Rule management ──────────────────────────────────────────────
  statement {
    sid    = "EventBridgeRuleManagement"
    effect = "Allow"
    actions = [
      "events:PutRule",
      "events:DeleteRule",
      "events:DescribeRule",
      "events:EnableRule",
      "events:DisableRule",
      "events:ListRules",
      "events:TagResource",
      "events:UntagResource",
      "events:ListTagsForResource",
    ]
    resources = [
      "arn:aws:events:*:${local.account_id}:rule/*-${var.environment}-*",
    ]
  }

  # ── EventBridge: Target management ────────────────────────────────────────────
  statement {
    sid    = "EventBridgeTargetManagement"
    effect = "Allow"
    actions = [
      "events:PutTargets",
      "events:RemoveTargets",
      "events:ListTargetsByRule",
    ]
    resources = [
      "arn:aws:events:*:${local.account_id}:rule/*-${var.environment}-*",
    ]
  }

  # ── EventBridge: Global operations ────────────────────────────────────────────
  statement {
    sid    = "EventBridgeGlobalOperations"
    effect = "Allow"
    actions = [
      "events:ListRules",
      "events:ListEventBuses",
    ]
    resources = ["*"]
  }

  # ── CloudWatch Logs: Step Function logs ───────────────────────────────────────
  # Standard path: /aws/{project_name}/{tool}/{stack_name}
  # Examples: /aws/clinical-rag-foundry/stepfunction/sf-medical-pdf-parser
  #           /aws/template/stepfunction/my-step-function
  statement {
    sid    = "CloudWatchLogsStepFunctions"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:DescribeLogGroups",
      "logs:TagLogGroup",
      "logs:UntagLogGroup",
      "logs:ListTagsLogGroup",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:ListTagsForResource",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DeleteResourcePolicy",
    ]
    resources = [
      # Standard path: /aws/{project_name}/{tool}/{stack_name}
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/*/stepfunction/*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/*/stepfunction/*:*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/*/lambda/*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/*/lambda/*:*",
      # Legacy paths (for backwards compatibility)
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/states/*-${var.environment}",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/states/*-${var.environment}:*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/lambda/*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/lambda/*:*",
    ]
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 5: Budget Guardian (SNS & Budgets)
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_budget" {

  # ── SNS: Topic management ──────────────────────────────────────────────────
  statement {
    sid    = "SNSTopicManagement"
    effect = "Allow"
    actions = [
      "sns:CreateTopic",
      "sns:DeleteTopic",
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:TagResource",
      "sns:UntagResource",
      "sns:ListTagsForResource",
    ]
    resources = [
      "arn:aws:sns:*:${local.account_id}:budget-alerts-*-${var.environment}",
    ]
  }

  # ── SNS: Topic policy management ───────────────────────────────────────────
  statement {
    sid    = "SNSTopicPolicyManagement"
    effect = "Allow"
    actions = [
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
    ]
    resources = [
      "arn:aws:sns:*:${local.account_id}:budget-alerts-*-${var.environment}",
    ]
  }

  # ── SNS: Subscription management ───────────────────────────────────────────
  statement {
    sid    = "SNSSubscriptionManagement"
    effect = "Allow"
    actions = [
      "sns:Subscribe",
      "sns:Unsubscribe",
      "sns:GetSubscriptionAttributes",
      "sns:SetSubscriptionAttributes",
      "sns:ListSubscriptionsByTopic",
    ]
    resources = [
      "arn:aws:sns:*:${local.account_id}:budget-alerts-*-${var.environment}",
    ]
  }

  # ── SNS: Global operations ─────────────────────────────────────────────────
  statement {
    sid    = "SNSGlobalOperations"
    effect = "Allow"
    actions = [
      "sns:ListTopics",
      "sns:ListSubscriptions",
    ]
    resources = ["*"]
  }

  # ── Budgets: Budget management ─────────────────────────────────────────────
  statement {
    sid    = "BudgetsManagement"
    effect = "Allow"
    actions = [
      "budgets:ViewBudget",
      "budgets:ModifyBudget",
      "budgets:CreateBudgetAction",
      "budgets:DeleteBudgetAction",
      "budgets:UpdateBudgetAction",
      "budgets:DescribeBudgetAction",
      "budgets:DescribeBudgetActionsForBudget",
      "budgets:TagResource",
      "budgets:UntagResource",
      "budgets:ListTagsForResource",
    ]
    resources = [
      "arn:aws:budgets::${local.account_id}:budget/*",
    ]
  }

  # ── Budgets: Global operations ─────────────────────────────────────────────
  statement {
    sid    = "BudgetsGlobalOperations"
    effect = "Allow"
    actions = [
      "budgets:DescribeBudgets",
    ]
    resources = ["*"]
  }
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 6: DynamoDB
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_dynamodb" {

  # ── DynamoDB: Table management ────────────────────────────────────────────────
  statement {
    sid    = "DynamoDBTableManagement"
    effect = "Allow"
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:DeleteTable",
      "dynamodb:DescribeTable",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:UpdateTable",
      "dynamodb:UpdateTimeToLive",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:UpdateContinuousBackups",
      "dynamodb:ListTagsOfResource",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
    ]
    resources = [
      "arn:aws:dynamodb:*:${local.account_id}:table/*-${var.environment}",
      "arn:aws:dynamodb:*:${local.account_id}:table/*-${var.environment}/*",
    ]
  }

  # ── DynamoDB: Global operations ───────────────────────────────────────────────
  statement {
    sid    = "DynamoDBGlobalOperations"
    effect = "Allow"
    actions = [
      "dynamodb:ListTables",
      "dynamodb:DescribeLimits",
    ]
    resources = ["*"]
  }

  # ── DynamoDB: Auto Scaling (for provisioned mode) ─────────────────────────────
  statement {
    sid    = "DynamoDBAutoScaling"
    effect = "Allow"
    actions = [
      "application-autoscaling:RegisterScalableTarget",
      "application-autoscaling:DeregisterScalableTarget",
      "application-autoscaling:DescribeScalableTargets",
      "application-autoscaling:PutScalingPolicy",
      "application-autoscaling:DeleteScalingPolicy",
      "application-autoscaling:DescribeScalingPolicies",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "application-autoscaling:service-namespace"
      values   = ["dynamodb"]
    }
  }
}

# ================================================
# IAM Policy Resources
# ================================================

resource "aws_iam_policy" "terraform_dynamodb" {
  name        = "TerraformDeployment-DynamoDB-${var.environment}"
  description = "DynamoDB policy for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_dynamodb.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-DynamoDB-${var.environment}"
  })
}

resource "aws_iam_policy" "terraform_budget" {
  name        = "TerraformDeployment-Budget-${var.environment}"
  description = "Budget Guardian policy (SNS, Budgets) for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_budget.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-Budget-${var.environment}"
  })
}

resource "aws_iam_policy" "terraform_core" {
  name        = "TerraformDeployment-Core-${var.environment}"
  description = "Core infrastructure policy (S3, KMS, SSM) for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_core.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-Core-${var.environment}"
  })
}

resource "aws_iam_policy" "terraform_iam" {
  name        = "TerraformDeployment-IAM-${var.environment}"
  description = "IAM and CloudTrail policy for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_iam.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-IAM-${var.environment}"
  })
}

resource "aws_iam_policy" "terraform_lambda" {
  name        = "TerraformDeployment-Lambda-${var.environment}"
  description = "Lambda and ECR policy for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_lambda.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-Lambda-${var.environment}"
  })
}

resource "aws_iam_policy" "terraform_stepfunctions" {
  name        = "TerraformDeployment-StepFunctions-${var.environment}"
  description = "Step Functions and EventBridge policy for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_stepfunctions.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-StepFunctions-${var.environment}"
  })
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 7: VPC & Networking
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_vpc" {

  # ── VPC: Core VPC management ─────────────────────────────────────────────────
  statement {
    sid    = "VPCManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateVpc",
      "ec2:DeleteVpc",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcAttribute",
      "ec2:ModifyVpcAttribute",
      "ec2:CreateTags",
      "ec2:DeleteTags",
      "ec2:DescribeTags",
    ]
    resources = ["*"]
  }

  # ── VPC: Subnets ─────────────────────────────────────────────────────────────
  statement {
    sid    = "SubnetManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateSubnet",
      "ec2:DeleteSubnet",
      "ec2:DescribeSubnets",
      "ec2:ModifySubnetAttribute",
    ]
    resources = ["*"]
  }

  # ── VPC: Internet Gateway ────────────────────────────────────────────────────
  statement {
    sid    = "InternetGatewayManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateInternetGateway",
      "ec2:DeleteInternetGateway",
      "ec2:DescribeInternetGateways",
      "ec2:AttachInternetGateway",
      "ec2:DetachInternetGateway",
    ]
    resources = ["*"]
  }

  # ── VPC: NAT Gateway ─────────────────────────────────────────────────────────
  statement {
    sid    = "NATGatewayManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateNatGateway",
      "ec2:DeleteNatGateway",
      "ec2:DescribeNatGateways",
    ]
    resources = ["*"]
  }

  # ── VPC: Elastic IPs ─────────────────────────────────────────────────────────
  statement {
    sid    = "ElasticIPManagement"
    effect = "Allow"
    actions = [
      "ec2:AllocateAddress",
      "ec2:ReleaseAddress",
      "ec2:DescribeAddresses",
      "ec2:AssociateAddress",
      "ec2:DisassociateAddress",
    ]
    resources = ["*"]
  }

  # ── VPC: Route Tables ────────────────────────────────────────────────────────
  statement {
    sid    = "RouteTableManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:DescribeRouteTables",
      "ec2:CreateRoute",
      "ec2:DeleteRoute",
      "ec2:ReplaceRoute",
      "ec2:AssociateRouteTable",
      "ec2:DisassociateRouteTable",
      "ec2:ReplaceRouteTableAssociation",
    ]
    resources = ["*"]
  }

  # ── VPC: Security Groups ─────────────────────────────────────────────────────
  statement {
    sid    = "SecurityGroupManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifySecurityGroupRules",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
    ]
    resources = ["*"]
  }

  # ── VPC: VPC Endpoints ───────────────────────────────────────────────────────
  statement {
    sid    = "VPCEndpointManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateVpcEndpoint",
      "ec2:DeleteVpcEndpoints",
      "ec2:DescribeVpcEndpoints",
      "ec2:DescribeVpcEndpointServices",
      "ec2:ModifyVpcEndpoint",
      "ec2:DescribePrefixLists",
    ]
    resources = ["*"]
  }

  # ── VPC: Flow Logs ───────────────────────────────────────────────────────────
  statement {
    sid    = "FlowLogsManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateFlowLogs",
      "ec2:DeleteFlowLogs",
      "ec2:DescribeFlowLogs",
    ]
    resources = ["*"]
  }

  # ── VPC: Network ACLs ────────────────────────────────────────────────────────
  statement {
    sid    = "NetworkACLManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkAcl",
      "ec2:DeleteNetworkAcl",
      "ec2:DescribeNetworkAcls",
      "ec2:CreateNetworkAclEntry",
      "ec2:DeleteNetworkAclEntry",
      "ec2:ReplaceNetworkAclEntry",
      "ec2:ReplaceNetworkAclAssociation",
    ]
    resources = ["*"]
  }

  # ── VPC: Availability Zones ──────────────────────────────────────────────────
  statement {
    sid    = "AvailabilityZonesDescribe"
    effect = "Allow"
    actions = [
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeRegions",
    ]
    resources = ["*"]
  }

  # ── VPC: Network Interfaces (ENI) ───────────────────────────────────────────
  statement {
    sid    = "NetworkInterfaceManagement"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:AttachNetworkInterface",
      "ec2:DetachNetworkInterface",
    ]
    resources = ["*"]
  }

  # ── RDS: Subnet Groups ───────────────────────────────────────────────────────
  statement {
    sid    = "RDSSubnetGroupManagement"
    effect = "Allow"
    actions = [
      "rds:CreateDBSubnetGroup",
      "rds:DeleteDBSubnetGroup",
      "rds:DescribeDBSubnetGroups",
      "rds:ModifyDBSubnetGroup",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:subgrp:*-${var.environment}-*",
      "arn:aws:rds:*:${local.account_id}:subgrp:*-${var.environment}",
    ]
  }

  # ── RDS: Describe operations ─────────────────────────────────────────────────
  statement {
    sid    = "RDSDescribeOperations"
    effect = "Allow"
    actions = [
      "rds:DescribeDBSubnetGroups",
    ]
    resources = ["*"]
  }

  # ── IAM: VPC Flow Logs role ──────────────────────────────────────────────────
  statement {
    sid    = "IAMFlowLogsRoleManagement"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-flow-logs-role",
    ]
  }

  # ── IAM: PassRole for VPC Flow Logs ──────────────────────────────────────────
  statement {
    sid     = "IAMPassRoleToFlowLogs"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-flow-logs-role",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["vpc-flow-logs.amazonaws.com"]
    }
  }

  # ── CloudWatch Logs: VPC Flow Logs ───────────────────────────────────────────
  statement {
    sid    = "CloudWatchLogsVPCFlowLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:DescribeLogGroups",
      "logs:TagLogGroup",
      "logs:UntagLogGroup",
      "logs:ListTagsLogGroup",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:ListTagsForResource",
    ]
    resources = [
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/vpc/*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/vpc/*:*",
    ]
  }
}

resource "aws_iam_policy" "terraform_vpc" {
  name        = "TerraformDeployment-VPC-${var.environment}"
  description = "VPC and Networking policy for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_vpc.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-VPC-${var.environment}"
  })
}

# ══════════════════════════════════════════════════════════════════════════════
# POLICY 7: RDS and Aurora Serverless
# ══════════════════════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "terraform_rds" {

  # ── RDS: Instance Management ────────────────────────────────────────────────
  statement {
    sid    = "RDSInstanceManagement"
    effect = "Allow"
    actions = [
      "rds:CreateDBInstance",
      "rds:DeleteDBInstance",
      "rds:ModifyDBInstance",
      "rds:RebootDBInstance",
      "rds:StartDBInstance",
      "rds:StopDBInstance",
      "rds:DescribeDBInstances",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:db*-${var.environment}",
      "arn:aws:rds:*:${local.account_id}:db*-${var.environment}-*",
    ]
  }

  # ── RDS: Aurora Cluster Management ──────────────────────────────────────────
  statement {
    sid    = "RDSClusterManagement"
    effect = "Allow"
    actions = [
      "rds:CreateDBCluster",
      "rds:DeleteDBCluster",
      "rds:ModifyDBCluster",
      "rds:StartDBCluster",
      "rds:StopDBCluster",
      "rds:DescribeDBClusters",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
      "rds:DescribeGlobalClusters"
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:*-${var.environment}",
      "arn:aws:rds:*:${local.account_id}:*-${var.environment}-*",
      "arn:aws:rds::${local.account_id}:global-cluster:*"
    ]
  }

  # ── RDS: Aurora Cluster Instance Management ─────────────────────────────────
  statement {
    sid    = "RDSClusterInstanceManagement"
    effect = "Allow"
    actions = [
      "rds:CreateDBInstance",
      "rds:DeleteDBInstance",
      "rds:ModifyDBInstance",
      "rds:DescribeDBInstances",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:db*-${var.environment}-instance-*",
    ]
  }

  # ── RDS: Parameter Groups ───────────────────────────────────────────────────
  statement {
    sid    = "RDSParameterGroupManagement"
    effect = "Allow"
    actions = [
      "rds:CreateDBParameterGroup",
      "rds:DeleteDBParameterGroup",
      "rds:ModifyDBParameterGroup",
      "rds:DescribeDBParameterGroups",
      "rds:DescribeDBParameters",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:*-${var.environment}-*",
    ]
  }

  # ── RDS: Cluster Parameter Groups ───────────────────────────────────────────
  statement {
    sid    = "RDSClusterParameterGroupManagement"
    effect = "Allow"
    actions = [
      "rds:CreateDBClusterParameterGroup",
      "rds:DeleteDBClusterParameterGroup",
      "rds:ModifyDBClusterParameterGroup",
      "rds:DescribeDBClusterParameterGroups",
      "rds:DescribeDBClusterParameters",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:cluster*-${var.environment}-*",
    ]
  }

  # ── RDS: Option Groups ──────────────────────────────────────────────────────
  statement {
    sid    = "RDSOptionGroupManagement"
    effect = "Allow"
    actions = [
      "rds:CreateOptionGroup",
      "rds:DeleteOptionGroup",
      "rds:ModifyOptionGroup",
      "rds:DescribeOptionGroups",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:og*-${var.environment}-*",
    ]
  }

  # ── RDS: Subnet Groups (extended from VPC policy) ───────────────────────────
  statement {
    sid    = "RDSSubnetGroupManagementExtended"
    effect = "Allow"
    actions = [
      "rds:CreateDBSubnetGroup",
      "rds:DeleteDBSubnetGroup",
      "rds:ModifyDBSubnetGroup",
      "rds:DescribeDBSubnetGroups",
      "rds:AddTagsToResource",
      "rds:RemoveTagsFromResource",
      "rds:ListTagsForResource",
    ]
    resources = [
      "arn:aws:rds:*:${local.account_id}:subgrp*-${var.environment}-*",
    ]
  }

  # ── RDS: Describe operations (no resource-level support) ───────────────────
  statement {
    sid    = "RDSDescribeAll"
    effect = "Allow"
    actions = [
      "rds:DescribeDBInstances",
      "rds:DescribeDBClusters",
      "rds:DescribeDBSubnetGroups",
      "rds:DescribeDBParameterGroups",
      "rds:DescribeDBClusterParameterGroups",
      "rds:DescribeOptionGroups",
      "rds:DescribeDBEngineVersions",
      "rds:DescribeOrderableDBInstanceOptions",
      "rds:DescribeDBClusterEndpoints",
    ]
    resources = ["*"]
  }

  # ── Secrets Manager: RDS Credentials ────────────────────────────────────────
  statement {
    sid    = "SecretsManagerRDSCredentials"
    effect = "Allow"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecret",
      "secretsmanager:TagResource",
      "secretsmanager:UntagResource",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:PutResourcePolicy",
      "secretsmanager:DeleteResourcePolicy",
    ]
    resources = [
      "arn:aws:secretsmanager:*:${local.account_id}:secret:*-${var.environment}-master-password-*",
    ]
  }

  # ── Secrets Manager: Random suffix lookup ───────────────────────────────────
  statement {
    sid    = "SecretsManagerDescribe"
    effect = "Allow"
    actions = [
      "secretsmanager:ListSecrets",
    ]
    resources = ["*"]
  }

  # ── IAM: RDS Enhanced Monitoring Role ───────────────────────────────────────
  statement {
    sid    = "IAMRDSMonitoringRoleManagement"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-rds-monitoring-role",
    ]
  }

  # ── IAM: PassRole for RDS Enhanced Monitoring ───────────────────────────────
  statement {
    sid     = "IAMPassRoleToRDSMonitoring"
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      "arn:aws:iam::${local.account_id}:role/*-${var.environment}-rds-monitoring-role",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["monitoring.rds.amazonaws.com"]
    }
  }

  # ── CloudWatch: RDS Alarms ──────────────────────────────────────────────────
  statement {
    sid    = "CloudWatchRDSAlarms"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:TagResource",
      "cloudwatch:UntagResource",
      "cloudwatch:ListTagsForResource",
    ]
    resources = [
      "arn:aws:cloudwatch:*:${local.account_id}:alarm:*-${var.environment}-*",
    ]
  }

  # ── CloudWatch Logs: RDS Logs ───────────────────────────────────────────────
  statement {
    sid    = "CloudWatchLogsRDS"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:DescribeLogGroups",
      "logs:TagLogGroup",
      "logs:UntagLogGroup",
      "logs:ListTagsLogGroup",
      "logs:TagResource",
      "logs:UntagResource",
      "logs:ListTagsForResource",
    ]
    resources = [
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/rds/*",
      "arn:aws:logs:*:${local.account_id}:log-group:/aws/rds/*:*",
    ]
  }

  # ── EC2: Security Groups for RDS ────────────────────────────────────────────
  statement {
    sid    = "EC2SecurityGroupsForRDS"
    effect = "Allow"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:CreateTags",
      "ec2:DeleteTags",
      "ec2:ModifySecurityGroupRules",
    ]
    resources = ["*"]
  }

  # ── EC2: VPC Read for RDS ───────────────────────────────────────────────────
  statement {
    sid    = "EC2VPCReadForRDS"
    effect = "Allow"
    actions = [
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeAvailabilityZones",
    ]
    resources = ["*"]
  }

  # ── KMS: RDS Encryption ─────────────────────────────────────────────────────
  statement {
    sid    = "KMSForRDSEncryption"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["rds.*.amazonaws.com", "secretsmanager.*.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "terraform_rds" {
  name        = "TerraformDeployment-RDS-${var.environment}"
  description = "RDS and Aurora Serverless policy for ${var.environment}"
  policy      = data.aws_iam_policy_document.terraform_rds.json

  tags = merge(var.tags, {
    Name = "TerraformDeployment-RDS-${var.environment}"
  })
}
