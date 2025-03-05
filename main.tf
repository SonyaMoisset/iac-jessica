# main.tf - Patch Corp's insecure infrastructure blueprint with expanded vulnerabilities

provider "aws" {
  region = "us-east-1"
}

##############################
# Compute and Networking Resources
##############################

# Vulnerable EC2 instance using an outdated AMI (Critical)
resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"  # Outdated/insecure AMI (not covered)
  instance_type = "t2.micro"
  security_groups = [aws_security_group.open_sg.name]
}

# Overly permissive security group (High)
resource "aws_security_group" "open_sg" {
  name        = "open_sg"
  description = "Security group with overly open inbound rules"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allows traffic from anywhere
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

##############################
# Storage and Logging
##############################

# Public and unencrypted S3 bucket (Critical)
resource "aws_s3_bucket" "patch_bucket" {
  bucket        = "patchcorp-bucket"
  acl           = "public-read"  # Publicly accessible
  force_destroy = true

  versioning {
    enabled = false  # Versioning disabled
  }
}

# Insecure S3 bucket for logs (High)
resource "aws_s3_bucket" "insecure_logs_bucket" {
  bucket        = "patchcorp-logs"
  acl           = "public-read"  # Publicly accessible logs
  force_destroy = true

  versioning {
    enabled = false  # No versioning enabled
  }
}

##############################
# Identity and Access Management
##############################

# IAM role with overly permissive assume policy (High)
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": { "AWS": "*" },
      "Effect": "Allow"
    }
  ]
}
EOF
}

# IAM policy with wildcard permissions (Critical)
resource "aws_iam_policy" "vulnerable_policy" {
  name   = "vulnerable_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",  
      "Resource": "*"
    }
  ]
}
EOF
}

# Attach the overly permissive policy to the role
resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.vulnerable_role.name
  policy_arn = aws_iam_policy.vulnerable_policy.arn
}

# IAM role for Lambda Function with overly permissive trust (Critical)
resource "aws_iam_role" "vulnerable_role" {
  name               = "vulnerable_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "*" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


# Overly permissive IAM policy for Lambda (Critical)
resource "aws_iam_policy" "lambda_policy" {
  name   = "lambda_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}

# Attach the policy to the Lambda role
resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

##############################
# Database Resources
##############################

# Insecure RDS instance (Critical)
resource "aws_db_instance" "insecure_db" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "5.6"  # Outdated engine version with known vulnerabilities (not covered)
  instance_class       = "db.t2.micro"
  username             = "admin"
  password             = "patch"  # Weak password stored in plain text (need to add a Rego custome rule here)
  publicly_accessible  = true   # Exposes the DB instance to the public internet
  skip_final_snapshot  = true
  storage_encrypted    = false  # Data not encrypted at rest
}

# package rules/ REGO RULE

# deny[msg] {
#   resource := input.resource.aws_db_instance[_]
#   resource.password
#   # Check if password is a literal string (i.e., not a computed reference)
#   not is_reference(resource.password)
#   msg := {
#     "publicId": "CUSTOM-DB-PLAIN",
#     "title": "Plaintext DB password detected",
#     "severity": "critical",
#     "msg": sprintf("Database instance %v uses a hardcoded password. Use a secure mechanism (e.g., AWS Secrets Manager) to manage credentials.", [resource.name]),
#     "remediation": "Remove the hardcoded password from the configuration and reference a secret stored securely.",
#     "references": []
#   }
# }

# # Helper function to check if a value is a reference (this is an illustrative example)
# is_reference(val) {
#   # In a real rule, you might check if the value is not a simple string literal,
#   # for example by testing its type or whether it contains interpolation markers.
#   false
# }

##############################
# Serverless and Monitoring
##############################

# Insecure Lambda Function (Critical)
resource "aws_lambda_function" "insecure_lambda" {
  function_name    = "insecureLambda"
  runtime          = "python3.8"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  filename         = "lambda_function.zip"
  source_code_hash = filebase64sha256("lambda_function.zip") 
  environment {
    variables = {
      AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7PATCH", # Hardcoded secret in environment variables
      AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCPATCHKEY",
      AWS_DEFAULT_REGION    = "us-west-2"
    }
  }
}

# Insecure CloudWatch Log Group (High)
resource "aws_cloudwatch_log_group" "insecure_logs" {
  name              = "/aws/lambda/insecureLambda"
  # retention_in_days = 0  # No retention period set, risking loss of log data (costs involved)
}

##############################
# Load Balancing
##############################

# Insecure Elastic Load Balancer (ELB) (High)
resource "aws_elb" "insecure_elb" {
  name               = "insecure-elb"
  availability_zones = ["us-east-1a"]

  listener {
    instance_port     = 80
    instance_protocol = "HTTP"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }

  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400
}
