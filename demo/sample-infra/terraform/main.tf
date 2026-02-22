terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# --- RDS: Unencrypted, No Backups ---

resource "aws_db_instance" "customer_data" {
  identifier     = "${var.environment}-customer-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage = 100
  db_name           = "customers"
  username          = "admin"
  password          = var.db_password

  storage_encrypted       = true
  kms_key_id              = "arn:aws:kms:eu-west-1:123456789012:key/your-kms-key-id" # Replace with your actual KMS Key ARN
  backup_retention_period = 7                                                        # Example: retain backups for 7 days
  multi_az                = true
  publicly_accessible     = false
  skip_final_snapshot     = true

  tags = {
    DataClass = "confidential"
    Contains  = "PII"
  }
}

# --- Security Group: Open to the world ---

resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Application security group"

  ingress {
    description = "Allow specific inbound traffic (e.g., HTTPS from trusted IPs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"] # Replace with actual trusted IP ranges
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- DORA Remediation: CloudTrail Logging ---

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "${var.environment}-cloudtrail-logs"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    enabled = true
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = "arn:aws:s3:::${var.environment}-cloudtrail-logs"
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${var.environment}-cloudtrail-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-cloudtrail-logs"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_public_access_block" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# --- DORA Remediation: CloudWatch Metric Alarms ---

resource "aws_sns_topic" "critical_alerts" {
  name = "${var.environment}-critical-system-alerts"
  tags = {
    Environment = var.environment
  }
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.critical_alerts.arn
  protocol  = "email"
  endpoint  = "security-team@example.com" # Replace with actual email
}

resource "aws_cloudwatch_metric_alarm" "rds_high_cpu_alarm" {
  alarm_name          = "${var.environment}-RDS-High-CPU-Utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 80 # 80% CPU utilization
  alarm_description   = "This alarm triggers when the average CPU utilization of the RDS instance is consistently high."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  ok_actions          = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.identifier
  }

  tags = {
    Environment = var.environment
    Service     = "Database"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_low_storage_alarm" {
  alarm_name          = "${var.environment}-RDS-Low-FreeStorageSpace"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Minimum"
  threshold           = 10000000000 # 10 GB (in bytes)
  alarm_description   = "This alarm triggers when the available storage space on the RDS instance falls below 10GB."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  ok_actions          = [aws_sns_topic.critical_alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.identifier
  }

  tags = {
    Environment = var.environment
    Service     = "Database"
  }
}