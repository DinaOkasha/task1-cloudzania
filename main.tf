terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "eu-west-1"
}

# Create a VPC
resource "aws_vpc" "task1_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true  # Enable DNS resolution
  enable_dns_hostnames = true # Enable DNS hostnames
  tags = {
    Name = "task1_vpc"
  }
}

variable "vpc_availability_zones" {
  type        = list(string)
  description = "Availability Zones"
  default     = ["eu-west-1a", "eu-west-1b"]
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.task1_vpc.id

  tags = {
    Name = "task1_vpc-igw"
  }

}
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.task1_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}



resource "aws_subnet" "public_subnet_a" {
  vpc_id                  = aws_vpc.task1_vpc.id
  cidr_block              = "10.0.5.0/24"  # Set the CIDR block
  availability_zone       = "eu-west-1a"   # Specify the availability zone
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-a"  # Set a static name for the public subnet
  }
}

resource "aws_subnet" "public_subnet_b" {
  vpc_id                  = aws_vpc.task1_vpc.id
  cidr_block              = "10.0.3.0/24"  # Set the CIDR block
  availability_zone       = "eu-west-1b"   # Specify the availability zone
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-b"  # Set a static name for the public subnet
  }
}

# Route Table Association for Public Subnet A
resource "aws_route_table_association" "public_association_a" {
  subnet_id      = aws_subnet.public_subnet_a.id  # Associate the route table with public subnet A
  route_table_id = aws_route_table.public_rt.id
}

# Route Table Association for Public Subnet B
resource "aws_route_table_association" "public_association_b" {
  subnet_id      = aws_subnet.public_subnet_b.id  # Associate the route table with public subnet B
  route_table_id = aws_route_table.public_rt.id
}
# Create Elastic IP for NAT Gateway
resource "aws_eip" "nat_eip" {
  domain = "vpc"  
}

# Create NAT Gateway
resource "aws_nat_gateway" "my_nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet_a.id  # Ensure this is a public subnet

  tags = {
    Name = "my-nat-gateway"
  }
}

# Create Route Table for Private Subnets
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.task1_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.my_nat_gateway.id
  }

  tags = {
    Name = "private-route-table"
  }
}
resource "aws_subnet" "private_subnet_a" {
  vpc_id                  = aws_vpc.task1_vpc.id
  cidr_block              = "10.0.1.0/24"  # CIDR block for the first subnet
  availability_zone       = "eu-west-1a"   # First AZ
  map_public_ip_on_launch = false           # This is a private subnet

  tags = {
    Name = "private-subnet-a"
  }
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id                  = aws_vpc.task1_vpc.id
  cidr_block              = "10.0.2.0/24"  # CIDR block for the second subnet
  availability_zone       = "eu-west-1b"   # Second AZ
  map_public_ip_on_launch = false           # This is a private subnet

  tags = {
    Name = "private-subnet-b"
  }
}

# Associate Route Table with Private Subnet A
resource "aws_route_table_association" "private_association_a" {
  subnet_id      = aws_subnet.private_subnet_a.id
  route_table_id = aws_route_table.private_rt.id
}

# Associate Route Table with Private Subnet B
resource "aws_route_table_association" "private_association_b" {
  subnet_id      = aws_subnet.private_subnet_b.id
  route_table_id = aws_route_table.private_rt.id
}


resource "aws_security_group" "rds_sg" {
  name        = "rds-sg"
  description = "Allow traffic to RDS from ECS"
  vpc_id      = aws_vpc.task1_vpc.id

  ingress {
    description = "Allow MySQL traffic from ECS service"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups  = [aws_security_group.ecs_service_sg.id]  # Only allow traffic from ECS
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allow outbound traffic to any destination
  }
}


resource "aws_security_group" "ecs_service_sg" {
  name        = "ecs-service-sg"
  description = "Allow traffic to ECS service"
  vpc_id      = aws_vpc.task1_vpc.id

  ingress {
    description = "Allow HTTP traffic from ALB"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Allow traffic only from ALB
  }

  ingress {
    description = "Allow traffic from RDS on port 3306"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Allow traffic from RDS (VPC CIDR)
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}



# IAM Role for ECS Tasks to Access RDS
resource "aws_iam_role" "ecs_task_rds_access" {
  name = "ecs-task-rds-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# Create a custom IAM policy for RDS access
resource "aws_iam_policy" "rds_access_policy" {
  name        = "RDSAccessPolicy"
  description = "Policy to allow ECS tasks to access RDS"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "rds:DescribeDBInstances",
          "rds:Connect"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach the custom policy to the ECS task role
resource "aws_iam_role_policy_attachment" "ecs_task_rds_access" {
  role       = aws_iam_role.ecs_task_rds_access.name
  policy_arn = aws_iam_policy.rds_access_policy.arn
}



resource "aws_secretsmanager_secret" "database_secret" {
  name = "wordpress-db-secret"
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id     = aws_secretsmanager_secret.database_secret.id
  secret_string = jsonencode({
    username = "wpuser",
    password = "Test1234!",
    host     = aws_db_instance.wordpress_rds.endpoint,
    db_name  = "wordpressdb"
  })
}


# Create the ECS Cluster
resource "aws_ecs_cluster" "ecs_cluster" {
  name = "ecs-wordpress-cluster"
}

# ECS Task Definition
resource "aws_ecs_task_definition" "wordpress_task" {
  family                = "wordpress-task"
  network_mode          = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn    = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn         = aws_iam_role.ecs_task_rds_access.arn 
  container_definitions = jsonencode([
    {
      name      = "wordpress-container"
      image     = "wordpress"
      essential = true
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
        }
      ]
     environment = [
    {
        name  = "WORDPRESS_DB_HOST"
        value = jsondecode(aws_secretsmanager_secret_version.db_credentials.secret_string)["host"]
    },
    {
        name  = "WORDPRESS_DB_USER"
        value = jsondecode(aws_secretsmanager_secret_version.db_credentials.secret_string)["username"]
    },
    {
        name  = "WORDPRESS_DB_PASSWORD"
        value = jsondecode(aws_secretsmanager_secret_version.db_credentials.secret_string)["password"]
    },
    {
        name  = "WORDPRESS_DB_NAME"
        value = jsondecode(aws_secretsmanager_secret_version.db_credentials.secret_string)["db_name"]
    }
]

    }
  ])
  memory   = "512"
  cpu      = "256"
}

# ECS Service
resource "aws_ecs_service" "wordpress_service" {
  name            = "wordpress-service"
  cluster         = aws_ecs_cluster.ecs_cluster.id
  task_definition = aws_ecs_task_definition.wordpress_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
    security_groups = [aws_security_group.ecs_service_sg.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.wordpress_tg.arn
    container_name   = "wordpress-container"
    container_port   = 80
  }

  depends_on = [aws_lb_listener.http]
}

resource "aws_security_group" "alb_sg" {
  name        = "alb-sg"
  description = "Allow traffic to ALB"
  vpc_id      = aws_vpc.task1_vpc.id

  ingress {
    description = "Allow HTTP traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow traffic from the internet
  }

  ingress {
    description = "Allow HTTPS traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow traffic from the internet
  }

  egress {
    description = "Allow traffic to ECS service"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.ecs_service_sg.id]  # Forward traffic to ECS service
  }
}
# RDS Instance
resource "aws_db_instance" "wordpress_rds" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  db_name              = "wordpressdb"
  username             = "wpuser"
  password             = "Test1234!"
  db_subnet_group_name = aws_db_subnet_group.wordpress_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  multi_az             = false
  publicly_accessible  = true
  skip_final_snapshot  = true
}

# DB Subnet Group
resource "aws_db_subnet_group" "wordpress_subnet_group" {
  name       = "wordpress-db-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
}



# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# Attach IAM Policies to Execution Role
resource "aws_iam_role_policy_attachment" "ecs_task_secrets_access" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonECS_FullAccess"
}

resource "aws_iam_role_policy_attachment" "ecs_task_secretsmanager_access" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

# ALB Configuration
resource "aws_lb" "wordpress_alb" {
  name               = "wordpress-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_subnet_a.id, aws_subnet.public_subnet_b.id]
}

resource "aws_lb_target_group" "wordpress_tg" {
  name     = "wordpress-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.task1_vpc.id
  target_type = "ip"
  
  health_check {
    path                = "/"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

resource "aws_route53_record" "wordpress_record" {
  zone_id = "Z0770151337G7J04A4517"  # Replace with your existing hosted zone ID
  name     = "ecs.everyoneget.click"  # Subdomain you want to use
  type     = "A"                       # Use "CNAME" if needed

  alias {
    name                   = aws_lb.wordpress_alb.dns_name
    zone_id                = aws_lb.wordpress_alb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_acm_certificate" "wordpress_cert" {
  domain_name       = "ecs.everyoneget.click"
  validation_method = "DNS"

  tags = {
    Name = "wordpress-cert"
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.wordpress_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  }
  
  allow_overwrite = true
  zone_id         = "Z0770151337G7J04A4517"
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record] 
 }

resource "aws_acm_certificate_validation" "cert_validation" {
  certificate_arn         = aws_acm_certificate.wordpress_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.wordpress_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.wordpress_cert.arn

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.wordpress_tg.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.wordpress_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      protocol = "HTTPS"
      port     = "443"
      status_code = "HTTP_301"
    }
  }
}

