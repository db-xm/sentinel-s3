/*resource "aws_athena_workgroup" "athena" {
  name = "xm-iac-tool-testing"

  configuration {
    result_configuration {
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn = 
      }
    }
  }
}

########################################################

resource "aws_cloudfront_distribution" "cloudfront" {
  origin {
    domain_name = aws_s3_bucket.bucket.bucket_regional_domain_name
    origin_id   = "xm-iac-tool-testing"

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  comment             = "Some comment"
  # default_root_object = "index.html"      # Root object should be specified

  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1_2016"     # TLS1 is not secure
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "iactest"
    cache_policy_id = aws_cloudfront_cache_policy.cache_policy.id

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }
}

resource "aws_cloudfront_cache_policy" "cache_policy" {
  name        = "example-policy"
  comment     = "test comment"
  default_ttl = 50
  max_ttl     = 100
  min_ttl     = 1
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "whitelist"
      cookies {
        items = ["example"]
      }
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["example"]
      }
    }
    query_strings_config {
      query_string_behavior = "whitelist"
      query_strings {
        items = ["example"]
      }
    }
  }
}

########################################################

variable "region" {
	type = string
	default = "eu-west-1"
}

locals {
	regions = [ "eu-west-2", "eu-west-3" ]
}

resource "aws_s3_bucket" "count_bucket" {
	count = var.region == "eu-west-1" ? 1 : 0

  bucket = "xm-iac-tool-testing-count-${var.region}"
}

resource "aws_s3_bucket" "for_each_bucket" {
	for_each = toset(local.regions)

	bucket = "xm-iac-tool-testing-for-each-${each.value}"
}

#########################################################

resource "aws_dynamodb_table" "dynamodb" {
  name = "xm-iac-tool-testing"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  range_key      = "GameTitle"
  server_side_encryption {
    enabled = false
  }

  attribute {
    name = "UserId"
    type = "S"
  }

  attribute {
    name = "GameTitle"
    type = "S"
  }

  attribute {
    name = "TopScore"
    type = "N"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled        = false
  }

  global_secondary_index {
    name               = "GameTitleIndex"
    hash_key           = "GameTitle"
    range_key          = "TopScore"
    write_capacity     = 10
    read_capacity      = 10
    projection_type    = "INCLUDE"
    non_key_attributes = ["UserId"]
  }
}

resource "aws_dax_cluster" "dax" {
  cluster_name                     = "xm-iac-tool-testing"
  iam_role_arn                     = aws_iam_role.dynamodb_role.arn
  node_type                        = "dax.r4.large"
  replication_factor               = 1
  cluster_endpoint_encryption_type = "NONE"
  security_group_ids = [ aws_security_group.dax_sg.id ]
  server_side_encryption {
    enabled = false
  }
}

resource "aws_security_group" "dax_sg" {
  name        = "BadDAXSG"
  description = "Purposely malformed security group"
  vpc_id      = "vpc-061a32e760b493dd6"

  ingress {
    description      = "Allow All"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

}

resource "aws_iam_role" "dynamodb_role" {
  name = "xm-iac-tool-testing-dynamodb"
  assume_role_policy = data.aws_iam_policy_document.dynamodb_assume_role_policy.json
}

data "aws_iam_policy_document" "dynamodb_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["dynamodb.amazonaws.com"]
    }
  }
}

##################################################################


resource "aws_instance" "ec2" {
  ami           = "ami-0ed752ea0f62749af"
  instance_type = "t3.micro"
  associate_public_ip_address = true

  # iam_instance_profile = 
  subnet_id = "subnet-053986b0c1187eb00"
  vpc_security_group_ids = [ aws_security_group.ec2_sg.id ]

  root_block_device {
    delete_on_termination = true
//    encrypted = true    # Setting to false causes apply to fail as there is a SCP against unencrypted volumes
//    kms_key_id = aws_kms_key.key.key_id
    volume_type = "gp3"
  }
}

resource "aws_security_group" "ec2_sg" {
  name        = "BadEC2SG"
  description = "Purposely malformed security group"
  vpc_id      = "vpc-061a32e760b493dd6"

  ingress {
    description      = "Allow All"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

}

########################################################

resource "aws_eks_cluster" "eks" {
  name     = "xm-iac-tool-testing"
  role_arn = aws_iam_role.eks_role.arn

  vpc_config {
    subnet_ids = ["subnet-0f1a67098d01ba80b", "subnet-02d788258419c254e", "subnet-0722963c0148d5b05"]   # R&D Public Subnets
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.example-AmazonEKSVPCResourceController,
  ]
}

data "aws_iam_policy_document" "eks_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eks_role" {
  name               = "xm-iac-tool-testing-eks"
  assume_role_policy = data.aws_iam_policy_document.eks_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_role.name
}

# Optionally, enable Security Groups for Pods
# Reference: https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html
resource "aws_iam_role_policy_attachment" "example-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_role.name
}

################################################################

resource "aws_elasticache_cluster" "elasticache" {
  cluster_id           = "xm-iac-tool-testing"
  engine               = "redis"
  node_type            = "cache.t2.small"
  num_cache_nodes      = 1
  network_type         = "ipv4"
  parameter_group_name = "default.redis7"
  engine_version       = "7.0"
  port                 = 6379
  security_group_ids = [ aws_security_group.elasticache_sg.id ]
  subnet_group_name = aws_elasticache_subnet_group.elasticache.name
}

resource "aws_elasticache_replication_group" "elasticache" {
  replication_group_id        = "xm-iac-tool-testing"
  description                 = "Replication Group"

  at_rest_encryption_enabled = false
  auth_token = "avoid-plaintext-passwords"
  node_type            = "cache.t2.small"
  security_group_ids = [ aws_security_group.elasticache_sg.id ]
  subnet_group_name = aws_elasticache_subnet_group.elasticache.name
  transit_encryption_enabled = false
}

resource "aws_security_group" "elasticache_sg" {
  name        = "BadElastiCacheSG"
  description = "Purposely malformed security group"
  vpc_id      = "vpc-061a32e760b493dd6"

  ingress {
    description      = "Allow All"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

}

resource "aws_elasticache_subnet_group" "elasticache" {
  name       = "xm-iac-tool-testing"
  subnet_ids = ["subnet-0f1a67098d01ba80b", "subnet-02d788258419c254e", "subnet-0722963c0148d5b05"] # R&D Public Subnets
}

#############################################################

resource "aws_lb" "lb" {
  name               = "xm-iac-tool-testing"
  internal           = false
  ip_address_type    = "ipv4"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = ["subnet-0f1a67098d01ba80b", "subnet-02d788258419c254e", "subnet-0722963c0148d5b05"] # R&D Public Subnets

}

resource "aws_security_group" "lb_sg" {
  name        = "BadLBSG"
  description = "Purposely malformed security group"
  vpc_id      = "vpc-061a32e760b493dd6"

  ingress {
    description      = "Allow All"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

}

resource "aws_lb_listener" "lb_https_listener" {
  load_balancer_arn = aws_lb.lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"   # Default policy that supports TLSv1 and TLSv1.1, which are not safe
  certificate_arn   = "arn:aws:acm:eu-west-1:874037324847:certificate/52dcd67a-422e-4667-9876-d77e4555783c"

  default_action {
    type             = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Fixed response content"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener" "lb_http_listener" {
  load_balancer_arn = aws_lb.lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Fixed response content"
      status_code  = "200"
    }
  }
}

##############################################################

resource "aws_iam_user" "user" {
  name = "xm-iac-tool-testing"
  path = "/"
}

resource "aws_iam_policy" "policy" {
  name        = "xm-iac-tool-testing"
  path        = "/"
  description = "Bad policy attached to a user."

  policy = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_user_policy_attachment" "attachment" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.policy.arn
}

data "aws_iam_policy_document" "policy" {
  statement {
    sid = "BadIAMPolicy"
    effect = "Allow"
    actions = ["s3:*"]

    resources = ["*"]
  }
}

############################################################

resource "aws_kinesis_stream" "kinesis" {
  name             = "xm-iac-tool-testing"
  encryption_type  = "NONE"
  shard_count      = 1
}

############################################################

resource "aws_kms_key" "key" {
  
}

resource "aws_kms_alias" "key" {
  name          = "alias/xm-iac-tool-testing"
  target_key_id = aws_kms_key.key.key_id
}

#############################################################

resource "aws_lambda_function" "lambda" {
  filename      = data.archive_file.lambda_source.output_path
  function_name = "xm-iac-tool-testing"
  role          = aws_iam_role.lambda_role.arn
  runtime       = "python3.10"
  handler       = "lambda.py"

  environment {
    variables = {
      foo = "AKIAIOSFODNN7EXAMAAA"
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "common_lambda_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": ["sts:AssumeRole"],
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "test_inline_policy"
  role = aws_iam_role.lambda_role.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "lambda:UpdateFunctionCode",      # Privilege Escalation
          "lambda:CreateFunction",
          "lambda:InvokeFunction",
          "iam:PassRole"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

data "archive_file" "lambda_source" {
  source_dir  = "./lambda"
  output_path = "lambda.zip"
  type        = "zip"
}

#############################################################

module "s3_remote" {
  source = "github.com/rackspace-infrastructure-automation/aws-terraform-s3"

  bucket_logging    = false
  environment       = "Development"
  name              = "xm-iac-tool-testing-remote"
  versioning        = true

  block_public_access_acl = false
  block_public_access_policy = false
  block_public_access_ignore_acl = false
  block_public_access_restrict_bucket = false

  tags = {
    RightSaid = "Fred"
    LeftSaid  = "George"
  }
}

module "s3_local" {
  source = "./modules"

  bucket_logging    = false
  environment       = "Development"
  name              = "xm-iac-tool-testing-local"
  versioning        = true

  block_public_access_acl = false
  block_public_access_policy = false
  block_public_access_ignore_acl = false
  block_public_access_restrict_bucket = false

  tags = {
    RightSaid = "Fred"
    LeftSaid  = "George"
  }
}


###################################################################

resource "aws_db_instance" "rds" {
  allocated_storage = 10
  db_name = "xmiactooltesting"
  db_subnet_group_name = aws_db_subnet_group.rds.id
  engine = "mysql"
  engine_version = "5.7"
  instance_class = "db.t3.micro"
  kms_key_id = aws_kms_key.key.arn
  storage_encrypted = true  # Setting to false causes apply to fail as there is a SCP against unencrypted databases
  username = "username"
  password = "avoid-plaintext-passwords"
  skip_final_snapshot = true
  vpc_security_group_ids = [ aws_security_group.rds_sg.id ]
}

resource "aws_rds_cluster" "rds" {
  cluster_identifier = "xmiactooltesting"
  db_subnet_group_name = aws_db_subnet_group.rds.id
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned"
  engine_version     = "13.6"
  database_name      = "xmiactooltesting"
  kms_key_id         = aws_kms_key.key.arn
  master_username    = "username"
  master_password    = "avoid-plaintext-passwords"
  storage_encrypted  = false  # Setting to false causes apply to fail as there is a SCP against unencrypted databases
  skip_final_snapshot = true
  vpc_security_group_ids = [ aws_security_group.rds_sg.id ]
}


resource "aws_db_subnet_group" "rds" {
  name       = "xm-iac-tool-testing"
  subnet_ids = ["subnet-0f1a67098d01ba80b", "subnet-02d788258419c254e", "subnet-0722963c0148d5b05"] # R&D Public Subnets
}

resource "aws_security_group" "rds_sg" {
  name        = "BadRDSSG"
  description = "Purposely malformed security group"
  vpc_id      = "vpc-061a32e760b493dd6"

  ingress {
    description      = "Allow All"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_db_parameter_group" "mysql" {
  name   = "rds-mysql"
  family = "mysql8.0"

  parameter {
    name  = "require_secure_transport"
    value = "0"
  }
}

resource "aws_rds_cluster_parameter_group" "aurora_mysql" {
  name   = "rds-aurora-mysql"
  family = "aurora-mysql8.0"

  parameter {
    name  = "require_secure_transport"
    value = "OFF"
  }
}

resource "aws_db_parameter_group" "postgres" {
  name   = "rds-postgres"
  family = "postgres14"

  parameter {
    name  = "rds.force_ssl"
    value = "0"
  }
}

#################################################################

resource "aws_redshift_cluster" "redshift" {
  cluster_identifier = "xm-iac-tool-testing"
  database_name      = "xm_iac_tool_testing"
  master_username    = "username"
  master_password    = "Avoid-plaintext-passwords1"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  encrypted          = false
  publicly_accessible = true
}

resource "aws_redshift_parameter_group" "redshift" {
  name   = "xm-iac-tool-testing"
  family = "redshift-1.0"

  parameter {
    name  = "require_ssl"
    value = "false"
  }
}

##############################################################

resource "aws_sns_topic" "topic" {
    name = "xm-iac-tool-testing"
    # policy = 
    # kms_master_key_id = ""
}

data "aws_iam_policy_document" "hello" {
  statement {
    sid       = "AllowPublishThroughSSLOnly"
    effect    = "Deny"
    resources = [aws_sns_topic.topic.arn]
    actions   = ["SNS:Publish"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

##############################################################

resource "aws_sqs_queue" "queue" {
  name                    = "xm-iac-tool-testing"
  sqs_managed_sse_enabled = false
  #kms_master_key_id = 
}

##############################################################

resource "aws_ssm_parameter" "ssm" {
  name = "xm-iac-tool-testing"
  type = "String"
  description = "Parameter stored unencrypted"
  value = "Use KMS for storing parameters"
}
*/
#################################################################

data "aws_canonical_user_id" "current" {}

resource "aws_s3_bucket" "bucket" {
  bucket = "xm-iac-tool-testing"
}

# Avoid wildcards in bucket policy actions and principal
# Enforce encryption in-transit
resource "aws_s3_bucket_policy" "bucket" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    sid = "BadBucketPolicy"
    effect = "Allow"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.bucket.arn,
      "${aws_s3_bucket.bucket.arn}/*",
    ]
  }
  statement {
    sid       = "GoodBucketPolicy"
    effect    = "Deny"
    resources = [
      aws_s3_bucket.bucket.arn,
      "${aws_s3_bucket.bucket.arn}/*",
    ]
    actions   = ["s3:*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Block public access settings to true
resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Public ACL
resource "aws_s3_bucket_ownership_controls" "bucket" {
  bucket = aws_s3_bucket.bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "acl_1" {
  depends_on = [
    aws_s3_bucket_ownership_controls.bucket,
    aws_s3_bucket_public_access_block.bucket,
  ]
  bucket = aws_s3_bucket.bucket.id
  acl    = "public-read-write"
}

/*resource "aws_s3_bucket_acl" "acl_2" {
  depends_on = [
    aws_s3_bucket_ownership_controls.bucket,
    aws_s3_bucket_public_access_block.bucket,
  ]
  bucket = aws_s3_bucket.bucket.id
  acl    = "public-read"
}*/

/*resource "aws_s3_bucket_acl" "acl_3" {
  depends_on = [
    aws_s3_bucket_ownership_controls.bucket,
    aws_s3_bucket_public_access_block.bucket,
  ]
  bucket = aws_s3_bucket.bucket.id
  access_control_policy {
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
      }
      permission = "READ_ACP"
    }
    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}*/

# Encryption at rest
    // This does not need a test case as it is not possible via Terraform or AWS console to create an S3 bucket with AWS-SSE disabled

##################################################################

provider "aws" {
  region = "eu-west-1"
}

