# =============================================================================
# Sample Production Infrastructure — Intentionally Non-Compliant
# =============================================================================
# WARNING: This file contains intentional security and compliance violations
# for demonstration and testing purposes. DO NOT deploy this configuration.
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
# VIOLATION: RDS Instance — Unencrypted, No Backups, No HA, No Monitoring
#
# Violates:
#   - DORA Art 9(3)(b)  — encryption of data at rest
#   - DORA Art 9(4)(c)  — data integrity and confidentiality
#   - DORA Art 11(1)    — backup and recovery
#   - GDPR Art 32(1)(a) — encryption of personal data
#   - GDPR Art 32(1)(c) — availability and resilience of processing systems
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

  # VIOLATION: Storage encryption disabled — data at rest is unprotected
  storage_encrypted = false
  # VIOLATION: No KMS key specified (kms_key_id omitted)

  # VIOLATION: Backup retention set to zero — no automated backups
  backup_retention_period = 0

  # VIOLATION: Multi-AZ disabled — single point of failure, no HA
  multi_az = false

  # VIOLATION: Enhanced monitoring disabled (monitoring_interval omitted)
  # VIOLATION: Performance Insights disabled (performance_insights_enabled omitted)

  publicly_accessible = false
  skip_final_snapshot = true

  tags = {
    Name        = "${var.environment}-customer-data"
    DataClass   = "confidential"
    Contains    = "PII"
  }
}

# -----------------------------------------------------------------------------
# VIOLATION: S3 Bucket — No Server-Side Encryption
#
# Violates:
#   - CIS AWS 2.1.1 — Ensure S3 bucket encryption is enabled
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data_lake" {
  bucket = "${var.environment}-comply-demo-data-lake"

  tags = {
    Name      = "${var.environment}-data-lake"
    DataClass = "internal"
  }
}

# VIOLATION: No aws_s3_bucket_server_side_encryption_configuration resource
# for the data_lake bucket. Data is stored unencrypted.

# VIOLATION: No aws_s3_bucket_public_access_block for the data_lake bucket
#
# Violates:
#   - CIS AWS 2.1.2 — Ensure S3 bucket policy is set to deny HTTP requests
#                      and public access is blocked

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id

  versioning_configuration {
    status = "Suspended"
  }
}

# -----------------------------------------------------------------------------
# VIOLATION: EC2 Instance — Detailed Monitoring Disabled
#
# Violates:
#   - DORA Art 10 — Detection of anomalous activities
# -----------------------------------------------------------------------------

resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.large"
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  # VIOLATION: Detailed monitoring disabled
  monitoring = false

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
# VIOLATION: Security Group — Unrestricted Inbound Access
#
# Violates:
#   - GDPR Art 32(1)(b) — Ability to ensure confidentiality of processing systems
#   - CIS AWS 4.1       — Ensure no security group allows ingress from 0.0.0.0/0
# -----------------------------------------------------------------------------

resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id

  # VIOLATION: All traffic allowed from any source
  ingress {
    description = "Allow all inbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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
# VIOLATION: Load Balancer Listener — HTTP (Unencrypted)
#
# Violates:
#   - DORA Art 9(3)(c) — Encryption of data in transit
# -----------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "${var.environment}-app-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.app_sg.id]
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
  port              = 80

  # VIOLATION: Using HTTP instead of HTTPS — data in transit is unencrypted
  protocol = "HTTP"

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
# VIOLATION: No CloudTrail Configuration
#
# Violates:
#   - DORA Art 10 — ICT-related incident detection and monitoring
#
# A compliant setup would include:
#   resource "aws_cloudtrail" "main" { ... }
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# VIOLATION: No CloudWatch Alarms
#
# Violates:
#   - DORA Art 12 — ICT-related incident classification and reporting
#
# A compliant setup would include:
#   resource "aws_cloudwatch_metric_alarm" "cpu_high" { ... }
#   resource "aws_cloudwatch_metric_alarm" "db_connections" { ... }
#   resource "aws_cloudwatch_metric_alarm" "error_rate" { ... }
# -----------------------------------------------------------------------------

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
