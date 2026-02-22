# =============================================================================
# Sample Production Infrastructure — Compliant Version
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
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
  description = "AWS region for deployments"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (e.g., dev, test, prod)"
  type        = string
  default     = "dev"
}

variable "db_password" {
  description = "Password for the RDS database"
  type        = string
  sensitive   = true
}

variable "db_kms_key_id" {
  description = "KMS key ARN for RDS storage encryption"
  type        = string
  # A default placeholder for demonstration. In a real environment, this should be explicitly set.
  default     = "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id" 
}

variable "lb_certificate_arn" {
  description = "ACM certificate ARN for the HTTPS load balancer listener"
  type        = string
  # A default placeholder for demonstration. In a real environment, this should be explicitly set.
  default     = "arn:aws:acm:us-east-1:123456789012:certificate/your-certificate-id" 
}

variable "admin_ssh_cidr" {
  description = "CIDR block for allowing SSH access to instances (e.g., your office IP)"
  type        = string
  default     = "203.0.113.1/32" # Example IP, replace with your actual trusted CIDR
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
# Helper Resources
# -----------------------------------------------------------------------------

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

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
# RDS Instance — Compliant Configuration
# -----------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet-group"
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]

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

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  storage_encrypted = true
  kms_key_id        = var.db_kms_key_id

  backup_retention_period = 7

  multi_az = true

  publicly_accessible = false
  skip_final_snapshot = true

  tags = {
    Name        = "${var.environment}-customer-data"
    DataClass   = "confidential"
    Contains    = "PII"
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket — Compliant Configuration
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data_lake" {
  bucket = "${var.environment}-comply-demo-data-lake-${random_id.bucket_suffix.hex}"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name      = "${var.environment}-data-lake"
    DataClass = "internal"
  }
}

resource "aws_s3_bucket_public_access_block" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id

  versioning_configuration {
    status = "Suspended"
  }
}

# -----------------------------------------------------------------------------
# EC2 Instance — Compliant Configuration
# -----------------------------------------------------------------------------

resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.large"
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.app_sg.id]

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
# Security Group — Restricted Inbound Access
# -----------------------------------------------------------------------------

resource "aws_security_group" "lb_public_sg" {
  name        = "${var.environment}-lb-public-sg"
  description = "Security group for public facing Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTP from trusted external sources"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]
  }

  ingress {
    description = "Allow HTTPS from trusted external sources"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-lb-public-sg"
  }
}

resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Security group for application servers and RDS database"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTP from Load Balancer"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.lb_public_sg.id]
  }

  ingress {
    description = "Allow PostgreSQL from application servers (self-referencing)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  ingress {
    description = "Allow SSH from Admin IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ssh_cidr]
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

# -----------------------------------------------------------------------------
# Load Balancer Listener — HTTPS (Encrypted)
# -----------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "${var.environment}-app-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_public_sg.id]
  subnets            = [aws_subnet.public.id, aws_subnet.private.id]

  tags = {
    Name = "${var.environment}-app-lb"
  }
}

resource "aws_lb_target_group" "app" {
  name     = "${var.environment}-app-tg"
  port     = 80
  protocol = "HTTP"
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

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.lb_certificate_arn

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
# CloudTrail Configuration
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.environment}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}-${var.region}-${random_id.bucket_suffix.hex}"
  acl    = "log-delivery-write"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name = "${var.environment}-cloudtrail-logs"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}


resource "aws_cloudtrail" "main_trail" {
  name                          = "${var.environment}-main-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  enable_logging                = true
  include_global_service_events = true
  
  tags = {
    Name = "${var.environment}-cloudtrail"
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Alarms
# -----------------------------------------------------------------------------

resource "aws_sns_topic" "critical_alerts" {
  name = "${var.environment}-critical-alerts-topic"
  tags = {
    Name = "${var.environment}-critical-alerts-topic"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_cpu_app_server" {
  alarm_name          = "${var.environment}-HighCPUUtilization-AppServer"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "Alarm when EC2 App Server CPU exceeds 80% for 10 minutes."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  ok_actions          = [aws_sns_topic.critical_alerts.arn]
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }

  tags = {
    Name = "${var.environment}-high-cpu-alarm"
  }
}

resource "aws_cloudwatch_metric_alarm" "db_free_storage_low" {
  alarm_name          = "${var.environment}-DBFreeStorageLow-CustomerData"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Minimum"
  threshold           = "10000000000"
  alarm_description   = "Alarm when RDS Customer Data Free Storage Space drops below 10GB."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]
  ok_actions          = [aws_sns_topic.critical_alerts.arn]
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.id
  }

  tags = {
    Name = "${var.environment}-db-storage-low-alarm"
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