terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }

  # recommend to write
  required_version = ">= 0.14.9"
}

provider "aws" {
  # aws credentials profile
  profile = "terraform-test"
  region  = "ap-northeast-1"
}

data "aws_iam_policy_document" "allow_describe_regions" {
  statement {
    effect    = "Allow"
    actions   = ["ec2:DescribeRegions"]
    resources = ["*"]
  }
}

module "iam_role_for_ec2" {
  source     = "./iam_role"
  name       = "iam-role-for-ec2"
  identifier = "ec2.amazonaws.com"
  policy     = data.aws_iam_policy_document.allow_describe_regions.json
}

##############################################
###  VPC (Public Network)
##############################################
resource "aws_vpc" "terraform_practice" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "terraform-practice"
  }
}

###  Multi AZ
resource "aws_subnet" "public_terraform_0" {
  vpc_id                  = aws_vpc.terraform_practice.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-northeast-1a"
  map_public_ip_on_launch = true

  tags = {
    "Name" = "public-subnet-1a"
  }
}

resource "aws_subnet" "public_terraform_1" {
  vpc_id                  = aws_vpc.terraform_practice.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "ap-northeast-1c"
  map_public_ip_on_launch = true

  tags = {
    "Name" = "public-subnet-1c"
  }
}

resource "aws_internet_gateway" "public_terraform" {
  vpc_id = aws_vpc.terraform_practice.id

  tags = {
    "Name" = "terraform-practice"
  }
}

resource "aws_route_table" "public_terraform" {
  vpc_id = aws_vpc.terraform_practice.id

  tags = {
    "Name" = "public-route-table"
  }
}

resource "aws_route" "public_terraform" {
  route_table_id         = aws_route_table.public_terraform.id
  gateway_id             = aws_internet_gateway.public_terraform.id
  destination_cidr_block = "0.0.0.0/0"
}

###  Multi AZ
resource "aws_route_table_association" "public_terraform_0" {
  subnet_id      = aws_subnet.public_terraform_0.id
  route_table_id = aws_route_table.public_terraform.id
}

resource "aws_route_table_association" "public_terraform_1" {
  subnet_id      = aws_subnet.public_terraform_1.id
  route_table_id = aws_route_table.public_terraform.id
}

##############################################
###  VPC (Private Network)
##############################################

###  Multi AZ
resource "aws_subnet" "private_terraform_0" {
  vpc_id                  = aws_vpc.terraform_practice.id
  cidr_block              = "10.0.65.0/24"
  availability_zone       = "ap-northeast-1a"
  map_public_ip_on_launch = false

  tags = {
    "Name" = "private-subnet-1a"
  }
}

resource "aws_subnet" "private_terraform_1" {
  vpc_id                  = aws_vpc.terraform_practice.id
  cidr_block              = "10.0.66.0/24"
  availability_zone       = "ap-northeast-1c"
  map_public_ip_on_launch = false

  tags = {
    "Name" = "private-subnet-1c"
  }
}

### Multi AZ
resource "aws_eip" "nat_gateway_0" {
  vpc        = true
  depends_on = [aws_internet_gateway.public_terraform]

  tags = {
    "Name" = "eip-0"
  }
}

resource "aws_eip" "nat_gateway_1" {
  vpc        = true
  depends_on = [aws_internet_gateway.public_terraform]

  tags = {
    "Name" = "eip-1"
  }
}

### Multi AZ
resource "aws_nat_gateway" "private_terraform_0" {
  allocation_id = aws_eip.nat_gateway_0.id
  subnet_id     = aws_subnet.public_terraform_0.id
  depends_on    = [aws_internet_gateway.public_terraform]

  tags = {
    "Name" = "nat-gateway-0"
  }
}

resource "aws_nat_gateway" "private_terraform_1" {
  allocation_id = aws_eip.nat_gateway_1.id
  subnet_id     = aws_subnet.public_terraform_1.id
  depends_on    = [aws_internet_gateway.public_terraform]

  tags = {
    "Name" = "nat-gateway-1"
  }
}

### Multi AZ
resource "aws_route_table" "private_terraform_0" {
  vpc_id = aws_vpc.terraform_practice.id

  tags = {
    "Name" = "private-route-table-0"
  }
}

resource "aws_route_table" "private_terraform_1" {
  vpc_id = aws_vpc.terraform_practice.id

  tags = {
    "Name" = "private-route-table-1"
  }
}

### Multi AZ
resource "aws_route" "private_terraform_0" {
  route_table_id         = aws_route_table.private_terraform_0.id
  nat_gateway_id         = aws_nat_gateway.private_terraform_0.id
  destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route" "private_terraform_1" {
  route_table_id         = aws_route_table.private_terraform_1.id
  nat_gateway_id         = aws_nat_gateway.private_terraform_1.id
  destination_cidr_block = "0.0.0.0/0"
}

### Multi AZ
resource "aws_route_table_association" "private_terraform_0" {
  subnet_id      = aws_subnet.private_terraform_0.id
  route_table_id = aws_route_table.private_terraform_0.id
}

resource "aws_route_table_association" "private_terraform_1" {
  subnet_id      = aws_subnet.private_terraform_1.id
  route_table_id = aws_route_table.private_terraform_1.id
}

##############################################
###   Security Group
##############################################

module "terraform_sg" {
  source      = "./security_group"
  name        = "module-sg"
  vpc_id      = aws_vpc.terraform_practice.id
  port        = 80
  cidr_blocks = ["0.0.0.0/0"]
}

##############################################
###   S3 bucket
##############################################
resource "aws_s3_bucket" "private" {
  bucket = "private-kc9xaskif-0921"

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
}

resource "aws_s3_bucket_public_access_block" "private" {
  bucket                  = aws_s3_bucket.private.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "public" {
  bucket = "public-kc9xaskif-0921"
  acl    = "public-read"

  cors_rule {
    allowed_origins = ["https://example.com"]
    allowed_methods = ["GET"]
    allowed_headers = ["*"]
    max_age_seconds = 3000
  }
}

# ALB access log
resource "aws_s3_bucket" "alb_log" {
  bucket = "alb-log-kc9xaskif-0921"

  lifecycle_rule {
    enabled = true

    expiration {
      days = 180
    }
  }
}

resource "aws_s3_bucket_policy" "alb_log" {
  bucket = aws_s3_bucket.alb_log.id
  policy = data.aws_iam_policy_document.alb_log.json
}

data "aws_iam_policy_document" "alb_log" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.alb_log.id}/*"]

    # https://docs.aws.amazon.com/ja_jp/elasticloadbalancing/latest/classic/enable-access-logs.html
    principals {
      type        = "AWS"
      identifiers = ["582318560864"]
    }
  }
}

##############################################
###  Load Balancer
##############################################
resource "aws_lb" "dev-1" {
  name               = "dev-1"
  load_balancer_type = "application"
  # ALBが「インターネット向け」or「VPC内部向け」なのか
  internal     = false
  idle_timeout = 60
  # 削除保護 本番環境での誤削除を避けるため
  enable_deletion_protection = false

  # ALBが所属するサブネット。異なるAZを入れる
  subnets = [
    aws_subnet.public_terraform_0.id,
    aws_subnet.public_terraform_1.id,
  ]

  access_logs {
    bucket  = aws_s3_bucket.alb_log.id
    enabled = true
  }

  security_groups = [
    module.http_sg.security_group_id,
    module.https_sg.security_group_id,
    module.http_redirect_sg.security_group_id,
  ]
}

output "alb_dns_name" {
  value = aws_lb.dev-1.dns_name
}

module "http_sg" {
  source      = "./security_group"
  name        = "http-sg"
  vpc_id      = aws_vpc.terraform_practice.id
  port        = 80
  cidr_blocks = ["0.0.0.0/0"]
}

module "https_sg" {
  source      = "./security_group"
  name        = "https-sg"
  vpc_id      = aws_vpc.terraform_practice.id
  port        = 443
  cidr_blocks = ["0.0.0.0/0"]
}

module "http_redirect_sg" {
  source      = "./security_group"
  name        = "http-redirect-sg"
  vpc_id      = aws_vpc.terraform_practice.id
  port        = 8080
  cidr_blocks = ["0.0.0.0/0"]
}

# リスナーでどのポートのリクエストを受け付けるかを設定する
# リスナーはALBに複数アタッチできる
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.dev-1.arn
  port              = "80"
  protocol          = "HTTP"

  # リスナーは複数のルールを設定して、異なるアクションを実行可能
  # もし、どのルールにも合致しない場合は、default_actionが実行される
  # forward: リクエストを別のターゲットグループに転送
  # fixed-response: 固定のHTTPレスポンスを応答
  # redirect: 別のURLにリダイレクト
  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "これは『HTTP』です"
      status_code  = "200"
    }
  }
}

##############################################
###  Route53
# ドメイン登録はTerraformで実行できない
##############################################
# data "aws_route53_zone" "dev-1" {
#   name = "example.com"
# }
