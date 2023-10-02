provider "aws" {
  region = local.region

  # Make it faster by skipping something
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}

locals {
  bucket_name = "s3-bucket-${random_pet.this.id}"
  region      = "eu-west-1"
}

data "aws_caller_identity" "current" {}

data "aws_canonical_user_id" "current" {}

data "aws_cloudfront_log_delivery_canonical_user_id" "cloudfront" {}

resource "random_pet" "this" {
  length = 2
}

resource "aws_kms_key" "objects" {
  description             = "KMS key is used to encrypt bucket objects"
  deletion_window_in_days = 7
}

resource "aws_iam_role" "this" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.this.arn]
    }

    actions = [
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::${local.bucket_name}",
    ]
  }
}

module "s3_bucket" {
  //source = "./modules"
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git"

  bucket = local.bucket_name

  force_destroy       = true
  acceleration_status = "Suspended"
  request_payer       = "BucketOwner"

  tags = {
    Classification = "Anton"
  }

  # Note: Object Lock configuration can be enabled only on new buckets
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object_lock_configuration
  object_lock_enabled = true
  object_lock_configuration = {
    rule = {
      default_retention = {
        mode = "GOVERNANCE"
        days = 1
      }
    }
  }

  # Bucket policies
  attach_policy                            = true
  policy                                   = data.aws_iam_policy_document.bucket_policy.json
  attach_deny_insecure_transport_policy    = true
  attach_require_latest_tls_policy         = true
  attach_deny_incorrect_encryption_headers = true
  attach_deny_incorrect_kms_key_sse        = true
  allowed_kms_key_arn                      = aws_kms_key.objects.arn
  attach_deny_unencrypted_object_uploads   = true

  # S3 bucket-level Public Access Block configuration (by default now AWS has made this default as true for S3 bucket-level block public access)
  # block_public_acls       = true
  # block_public_policy     = true
  # ignore_public_acls      = true
  # restrict_public_buckets = true

  # S3 Bucket Ownership Controls
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"

  expected_bucket_owner = data.aws_caller_identity.current.account_id

  acl = "private" # "acl" conflicts with "grant" and "owner"

  versioning = {
    status     = true
    mfa_delete = false
  }

  website = {
    # conflicts with "error_document"
    #        redirect_all_requests_to = {
    #          host_name = "https://modules.tf"
    #        }

    index_document = "index.html"
    error_document = "error.html"
    routing_rules = [{
      condition = {
        key_prefix_equals = "docs/"
      },
      redirect = {
        replace_key_prefix_with = "documents/"
      }
      }, {
      condition = {
        http_error_code_returned_equals = 404
        key_prefix_equals               = "archive/"
      },
      redirect = {
        host_name          = "archive.myhost.com"
        http_redirect_code = 301
        protocol           = "https"
        replace_key_with   = "not_found.html"
      }
    }]
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = aws_kms_key.objects.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  cors_rule = [
    {
      allowed_methods = ["PUT", "POST"]
      allowed_origins = ["https://modules.tf", "https://terraform-aws-modules.modules.tf"]
      allowed_headers = ["*"]
      expose_headers  = ["ETag"]
      max_age_seconds = 3000
      }, {
      allowed_methods = ["PUT"]
      allowed_origins = ["https://example.com"]
      allowed_headers = ["*"]
      expose_headers  = ["ETag"]
      max_age_seconds = 3000
    }
  ]

  lifecycle_rule = [
    {
      id      = "log"
      enabled = true

      filter = {
        tags = {
          some    = "value"
          another = "value2"
        }
      }

      transition = [
        {
          days          = 30
          storage_class = "ONEZONE_IA"
          }, {
          days          = 60
          storage_class = "GLACIER"
        }
      ]

      #        expiration = {
      #          days = 90
      #          expired_object_delete_marker = true
      #        }

      #        noncurrent_version_expiration = {
      #          newer_noncurrent_versions = 5
      #          days = 30
      #        }
    },
    {
      id                                     = "log1"
      enabled                                = true
      abort_incomplete_multipart_upload_days = 7

      noncurrent_version_transition = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
        {
          days          = 60
          storage_class = "ONEZONE_IA"
        },
        {
          days          = 90
          storage_class = "GLACIER"
        },
      ]

      noncurrent_version_expiration = {
        days = 300
      }
    },
    {
      id      = "log2"
      enabled = true

      filter = {
        prefix                   = "log1/"
        object_size_greater_than = 200000
        object_size_less_than    = 500000
        tags = {
          some    = "value"
          another = "value2"
        }
      }

      noncurrent_version_transition = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
      ]

      noncurrent_version_expiration = {
        days = 300
      }
    },
  ]

  intelligent_tiering = {
    general = {
      status = "Enabled"
      filter = {
        prefix = "/"
        tags = {
          Environment = "dev"
        }
      }
      tiering = {
        ARCHIVE_ACCESS = {
          days = 180
        }
      }
    },
    documents = {
      status = false
      filter = {
        prefix = "documents/"
      }
      tiering = {
        ARCHIVE_ACCESS = {
          days = 125
        }
        DEEP_ARCHIVE_ACCESS = {
          days = 200
        }
      }
    }
  }

  metric_configuration = [
    {
      name = "documents"
      filter = {
        prefix = "documents/"
        tags = {
          priority = "high"
        }
      }
    },
    {
      name = "other"
      filter = {
        tags = {
          production = "true"
        }
      }
    },
    {
      name = "all"
    }
  ]
}

######################################
################ IAM #################
######################################

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

######################################
############### RDS ##################
######################################

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
  storage_encrypted  = true  # Setting to false causes apply to fail as there is a SCP against unencrypted databases
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

######################################
############### EC2 ##################
######################################


resource "aws_instance" "ec2" {
  ami           = "ami-0ed752ea0f62749af"
  instance_type = "t3.micro"
  associate_public_ip_address = true

  # iam_instance_profile = 
  subnet_id = "subnet-053986b0c1187eb00"
  vpc_security_group_ids = [ aws_security_group.ec2_sg.id ]

  root_block_device {
    delete_on_termination = true
    encrypted = true    # Setting to false causes apply to fail as there is a SCP against unencrypted volumes
    kms_key_id = aws_kms_key.key.key_id
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

