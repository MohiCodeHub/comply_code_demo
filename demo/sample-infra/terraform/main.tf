# =============================================================================
# Sample Production Infrastructure — Corrected for Compliance
# =============================================================================
# This file has been corrected to address identified security and compliance
# violations.
# =============================================================================

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

  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Project     = "comply-demo"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "db_password" {
  description = "Password for the RDS database"
  type        = string
  sensitive   = true
}

variable "kms_key_id" {
  description = "ARN of the KMS key for RDS encryption"
  type        = string
  # IMPORTANT: Replace with the ARN of your actual customer-managed KMS key.
  # Example: "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
}

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for the ALB HTTPS listener"
  type        = string
  # IMPORTANT: Replace with the ARN of your valid ACM certificate.
  # Example: "arn:aws:acm:us-east-1:123456789012:certificate/uuid"
}

variable "admin_cidr" {
  description = "CIDR block for administrator SSH access to EC2 instances. REMEDIATION: This MUST be restricted to specific trusted IP ranges (e.g., your office/VPN CIDR) for production. Do NOT use 0.0.0.0/0."
  type        = list(string)
  # Replace "<YOUR_SECURE_ADMIN_IP_RANGE>/32" with a specific, secure IP range.
  # Example: ["203.0.113.0/24"]
  default     = [] # Default to no SSH access. User must provide specific trusted IP ranges.
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# VPC & Networking
# -----------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.environment}-main-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "${var.environment}-private-subnet"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-igw"
  }
}

# -----------------------------------------------------------------------------
# Security Groups (Corrected for Least Privilege)
# -----------------------------------------------------------------------------

# Security group for the Application Load Balancer
resource "aws_security_group" "lb_sg" {
  name        = "${var.environment}-lb-sg"
  description = "Security group for application load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTPS access from WAF and internal networks" # REMEDIATION: Restrict to specific trusted IP ranges
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24", "10.0.0.0/16"] # Corrected: Restrict to specific trusted IP ranges (e.g., WAF or internal IPs)
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-lb-sg"
  }
}

# Security group for application servers (EC2 instances)
resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id

  # REMEDIATION: Restrict ingress to necessary ports and sources
  # Allow HTTP traffic from the Load Balancer's security group
  ingress {
    description     = "Allow HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_sg.id]
  }

  # Allow SSH access from admin CIDR
  ingress {
    description = "Allow SSH from admin IPs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-app-sg"
  }
}

# Security group for the RDS database
resource "aws_security_group" "db_sg" {
  name        = "${var.environment}-db-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  # REMEDIATION: Restrict ingress for DB to application servers only
  # Allow Postgres traffic from application servers' security group
  ingress {
    description     = "Allow Postgres from application servers"
    from_port       = 5432 # Default PostgreSQL port
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-db-sg"
  }
}

# -----------------------------------------------------------------------------
# RDS Instance (Corrected for encryption, backups, HA, monitoring)
# -----------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet-group"
  # REMEDIATION: Subnet group now uses only private subnet for database isolation
  subnet_ids = [aws_subnet.private.id]

  tags = {
    Name = "${var.environment}-db-subnet-group"
  }
}

resource "aws_db_instance" "customer_data" {
  identifier     = "${var.environment}-customer-data"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage     = 100
  max_allocated_storage = 500

  db_name  = "customers"
  username = "admin"
  password = var.db_password

  db_subnet_group_name = aws_db_subnet_group.main.name
  # REMEDIATION: Using a dedicated security group for the database
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  # REMEDIATION: Storage encryption enabled
  storage_encrypted = true
  # REMEDIATION: KMS key specified for enhanced control
  kms_key_id        = var.kms_key_id

  # REMEDIATION: Backup retention configured (7 days)
  backup_retention_period = 7

  # REMEDIATION: Multi-AZ enabled for High Availability and resilience
  multi_az = true

  # REMEDIATION: Enhanced monitoring enabled (60 seconds interval)
  monitoring_interval = 60

  # REMEDIATION: Performance Insights enabled
  performance_insights_enabled          = true
  performance_insights_retention_period = 7 # 7 days retention

  publicly_accessible = false
  skip_final_snapshot = false # Recommended to enable final snapshot in production

  tags = {
    Name        = "${var.environment}-customer-data"
    DataClass   = "confidential"
    Contains    = "PII"
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket (Corrected for Server-Side Encryption and Public Access Block)
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data_lake" {
  bucket = "${var.environment}-comply-demo-data-lake-${data.aws_caller_identity.current.account_id}"

  # REMEDIATION: Server-side encryption configuration added for data at rest
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256" # Using S3-managed keys; "aws:kms" for KMS keys
      }
    }
  }

  tags = {
    Name      = "${var.environment}-data-lake"
    DataClass = "internal"
  }
}

# REMEDIATION: aws_s3_bucket_public_access_block added to prevent public access
resource "aws_s3_bucket_public_access_block" "data_lake_public_access_block" {
  bucket                  = aws_s3_bucket.data_lake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id

  versioning_configuration {
    status = "Suspended" # Keeping original status as no remediation plan specified change
  }
}

# -----------------------------------------------------------------------------
# EC2 Instance (Corrected for Detailed Monitoring)
# -----------------------------------------------------------------------------

resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.large"
  subnet_id     = aws_subnet.public.id

  # REMEDIATION: Using the specific app_sg for the EC2 instance
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  # REMEDIATION: Detailed monitoring enabled for better visibility
  monitoring = true

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y docker.io
    systemctl enable docker
    systemctl start docker
    docker run -d -p 80:80 nginx:latest
  EOF

  tags = {
    Name = "${var.environment}-app-server"
    Role = "application"
  }
}

# -----------------------------------------------------------------------------
# Load Balancer Listener (Corrected for HTTPS)
# -----------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "${var.environment}-app-lb"
  internal           = false
  load_balancer_type = "application"
  # REMEDIATION: Using a dedicated security group for the load balancer
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = [aws_subnet.public.id, aws_subnet.private.id]

  tags = {
    Name = "${var.environment}-app-lb"
  }
}

resource "aws_lb_target_group" "app" {
  name     = "${var.environment}-app-tg"
  port     = 80
  protocol = "HTTP" # Target group protocol can remain HTTP for backend communication
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/health"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 10
    timeout             = 60
    interval            = 300
  }

  tags = {
    Name = "${var.environment}-app-tg"
  }
}

# REMEDIATION: Changed to HTTPS listener for encryption of data in transit
resource "aws_lb_listener" "https" { # Renamed from "http"
  load_balancer_arn = aws_lb.app.arn
  port              = 443 # Changed from 80

  # REMEDIATION: Using HTTPS protocol
  protocol          = "HTTPS"
  # REMEDIATION: SSL Policy and ACM Certificate ARN added
  ssl_policy        = "ELBSecurityPolicy-2016-08" # Recommended secure policy
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app_server.id
  port             = 80
}

# -----------------------------------------------------------------------------
# CloudTrail Configuration (Added for Incident Detection)
# -----------------------------------------------------------------------------

# REMEDIATION: S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.environment}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  acl    = "private" # Ensure bucket is private

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  # Best practice: Add lifecycle rules, MFA delete, and bucket policy for strict access
}

# REMEDIATION: CloudTrail enabled for comprehensive API logging
resource "aws_cloudtrail" "main_trail" {
  name                          = "${var.environment}-main-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true # Recommended for comprehensive logging
  enable_logging                = true
  include_global_service_events = true

  # Recommended: Integrate with CloudWatch Logs for real-time monitoring and alerting
  # cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail_log_group.arn
  # cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_role.arn
}

# -----------------------------------------------------------------------------
# CloudWatch Alarms (Added for Incident Classification and Reporting)
# -----------------------------------------------------------------------------

# REMEDIATION: SNS Topic for critical alerts notifications
resource "aws_sns_topic" "critical_alerts" {
  name = "${var.environment}-CriticalAlertsTopic"
}

# REMEDIATION: CloudWatch Metric Alarm for high CPU utilization on app server
resource "aws_cloudwatch_metric_alarm" "high_cpu_app_server" {
  alarm_name          = "${var.environment}-HighCPUUtilization-AppServer"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300" # 5 minutes
  statistic           = "Average"
  threshold           = "80" # Percentage
  alarm_description   = "Alarm when EC2 App Server CPU exceeds 80% for 10 minutes."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  ok_actions          = [aws_sns_topic.critical_alerts.arn]
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}

# REMEDIATION: CloudWatch Metric Alarm for low free storage on DB instance
resource "aws_cloudwatch_metric_alarm" "db_free_storage_low" {
  alarm_name          = "${var.environment}-DBFreeStorageLow-CustomerData"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = "300" # 5 minutes
  statistic           = "Minimum"
  threshold           = "10000000000" # Example: 10GB in bytes
  alarm_description   = "Alarm when RDS Customer Data Free Storage Space drops below 10GB."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  ok_actions          = [aws_sns_topic.critical_alerts.arn]
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.id
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "db_endpoint" {
  description = "RDS endpoint for the customer database"
  value       = aws_db_instance.customer_data.endpoint
}

output "app_server_public_ip" {
  description = "Public IP of the application server"
  value       = aws_instance.app_server.public_ip
}

output "lb_dns_name" {
  description = "DNS name of the application load balancer"
  value       = aws_lb.app.dns_name
}

output "data_lake_bucket" {
  description = "Name of the S3 data lake bucket"
  value       = aws_s3_bucket.data_lake.id
}