# Sample Production Infrastructure — Intentionally Non-Compliant
# WARNING: DO NOT deploy this configuration.

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

# --- RDS: Compliant with Encryption, Backups, Multi-AZ ---

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
  kms_key_id              = "arn:aws:kms:${var.region}:123456789012:key/your-kms-key-id" # REMINDER: Replace with your actual KMS key ARN
  backup_retention_period = 7 # Retain backups for 7 days
  multi_az                = true
  publicly_accessible     = false
  skip_final_snapshot     = true

  tags = {
    DataClass = "confidential"
    Contains  = "PII"
  }
}

# --- Security Group: Restricted access ---

resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Application security group"

  # REMINDER: Restrict ingress further to specific IPs or other security groups as needed.
  # This example allows HTTPS from anywhere, replace 0.0.0.0/0 if not publicly accessible.
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    # Remediation: Restrict ingress from 0.0.0.0/0 to specific trusted CIDR blocks
    cidr_blocks = ["192.168.1.0/24", "10.0.0.0/16"] # Example: Restrict to internal networks
    description = "Allow HTTPS from trusted sources"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- CloudTrail: Comprehensive logging for audit and security ---

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "${var.environment}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false # Set to true to allow bucket deletion even if it contains objects

  # Enable server-side encryption by default
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  # Public access is blocked via the dedicated aws_s3_bucket_public_access_block resource
  tags = {
    Environment = var.environment
    Service     = "CloudTrail"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_public_access_block" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:GetBucketAcl",
        Resource  = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid       = "AWSCloudTrailWrite",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-main-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  tags = {
    Environment = var.environment
    Service     = "CloudTrail"
  }
}

# --- CloudWatch Metric Alarms: Monitoring for critical events ---

resource "aws_sns_topic" "critical_alerts" {
  name = "${var.environment}-critical-alerts"
  tags = {
    Environment = var.environment
    Service     = "Monitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "db_cpu_high" {
  alarm_name          = "${var.environment}-db-cpu-utilization-high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "This alarm monitors DB CPU utilization and alerts if it's consistently high."
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.id
  }
  tags = {
    Environment = var.environment
    Service     = "Monitoring"
  }
}

data "aws_caller_identity" "current" {}

# Add necessary variables if they don't already exist in variables.tf
/*
variable "environment" {
  description = "The deployment environment (e.g., dev, prod)"
  type        = string
}

variable "region" {
  description = "The AWS region to deploy resources into."
  type        = string
  default     = "eu-west-1" # Example default region
}

variable "db_password" {
  description = "Password for the RDS database"
  type        = string
  sensitive   = true
}
*/