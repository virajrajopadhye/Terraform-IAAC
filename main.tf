variable "region" {
  # type = string
  default = "us-east-1"  
}

provider "aws" {
   region = var.region
}

variable "DYNAMO_NAME" {
  default= "csye6225"
}

variable "deployment_group" {
  default= "csye6225-webapp-deployment"
}

variable "domain_name" {
  default= "prod.virajrajopadhye.me"
}

variable "my_bucket"{
  default= "webapp.viraj.rajopadhye"
}


variable "codedeploybucket"{
  default= "codedeploy.virajrajopadhye.me.prod"
}

variable "aws_account_id" {
  # type = string
  # description = "AWS account id."
  default= "318863692788"
  
}

variable "application_name"{
  default = "csye6225-webapp"
}

variable "cicd"{
  default = "cicd"

}
variable "circleci"{
  default = "circleci"

}
# ####################################################################################
# RDS VARIABLES


variable "ALLOCATED_STORAGE"{
  default= "20"
}
variable "storage_type"{
  default= "gp2"
}
variable "engine"{
  default= "mysql"
}
variable "engine_version"{
  default= "5.7"
}
variable "identifier"{
  default= "csye6225-su2020"
}
variable "instance_class"{
  default= "db.t3.micro"
}
variable "name"{
  default= "csye6225"
}
variable "username"{
  default= "csye6225su2020"
}
variable "password"{
  default= "MySql020"
}
variable "parameter_group_name"{
  default= "default.mysql5.7"
}


################################RDS VARIABLE END#####################################


################################ EC2 VAriables ######################################
variable "instance_type"{
  default= "t2.micro"
}
variable "my_key"{
  default= "Viraj_CSYE6225"
}

variable "EC2_ROOT_VOLUME_SIZE"{
  default= "20"
}

variable "EC2_ROOT_VOLUME_TYPE"{
  default= "gp2"
}

variable "image_id" {
  type = string
  description = "The id of the machine image (AMI) to use for the server." 
  
}


################################ EC2 VAriables End ######################################




variable "cidr_range" {
  default = "172.16.0.0/16"
}

variable "public_cidrs" {
  type    = list(string)
  default = ["172.16.1.0/24", "172.16.2.0/24", "172.16.3.0/24"]
}

variable "cidr_block" {
  default = "0.0.0.0/0"
}

data "aws_availability_zones" "available" {
}

#############################################################################################################

#VPC Creation
resource "aws_vpc" "main" {
  cidr_block           = var.cidr_range
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "my-terraform-vpc"
  }
}

#############################################################################################################

#Creating IG
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "m-terraform-internet-gateway"
  }
}

#############################################################################################################

#Route Table
resource "aws_route_table" "public_route" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = var.cidr_block
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "my-terraform-public-route-table"
  }
}

#############################################################################################################

#subnets
resource "aws_subnet" "public_subnet" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_cidrs[count.index]
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "public-subnet-${count.index + 1}"
  }
}

#############################################################################################################

#Route table Association
resource "aws_route_table_association" "pub_sub_association" {
  count          = 3
  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public_route.id
  depends_on = [
    aws_route_table.public_route,
    aws_subnet.public_subnet,
  ]
}

#############################################################################################################

#Application Security Group
resource "aws_security_group" "application" {
  name        = "application"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  # ingress {
  #   description = "SSH"
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = [var.cidr_block]
  #   # security_groups = ["${aws_security_group.loadBalancer.id}"]
  # }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = ["${aws_security_group.loadBalancer.id}"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = ["${aws_security_group.loadBalancer.id}"]
  }

  ingress {
    description = "Custom TCP"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = ["${aws_security_group.loadBalancer.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr_block]
  }

  tags = {
    Name = "application-security-group"
  }
}

#############################################################################################################
#Database Security Group
resource "aws_security_group" "database" {
  name        = "database"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.main.id}"

  ingress {
    description = "MySQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    # cidr_blocks = [var.cidr_block]
    security_groups = ["${aws_security_group.application.id}"]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr_block]
  }

  tags = {
    Name = "database-security-group"
  }
}
#############################################################################################################
#Load Balancer Security Group
resource "aws_security_group" "loadBalancer" {
  name        = "loadBalancer"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.main.id}"

  # ingress {
  #   description = "HTTP"
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = [var.cidr_block]
  # }

   ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr_block]
  }

  tags = {
    Name = "loadBalancer-security-group"
  }
}

#############################################################################################################

#My s3 bucket
resource "aws_s3_bucket" "my_s3_bucket_resource" {

        bucket = var.my_bucket

        force_destroy = true

        acl    = "private"

        versioning {
            enabled = true
        }

        

        lifecycle_rule {
            id      = "log"
            enabled = true

            prefix = "log/"

            tags = {
              "rule"      = "log"
              "autoclean" = "true"
            }

            transition {
              days          = 30
              storage_class = "STANDARD_IA" # or "ONEZONE_IA"
            }

      }

        server_side_encryption_configuration {
            rule {
              apply_server_side_encryption_by_default {
              # kms_master_key_id = "${aws_kms_key.mykey.arn}"
              sse_algorithm = "AES256"
            }
          }
        }


    }

#############################################################################################################

#RDS instance

resource "aws_db_instance" "myRDSinstance" {
  allocated_storage    = var.ALLOCATED_STORAGE
  storage_type         = var.storage_type
  engine               = var.engine
  engine_version       = var.engine_version
  multi_az             = false
  identifier           = var.identifier
  instance_class       = var.instance_class
  name                 = var.name
  username             = var.username
  password             = var.password
  parameter_group_name = "${aws_db_parameter_group.param-group-rds.name}"
  publicly_accessible  = true
  skip_final_snapshot  = true
  storage_encrypted      = true
  # ca_cert_identifier     = "rds-ca-2019"
  db_subnet_group_name = "${aws_db_subnet_group.rds_subnet.name}"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
}


resource "aws_db_parameter_group" "param-group-rds" {
  name   = "param-group-rds"
  family = "mysql5.7"

  parameter {
    name  = "performance_schema"
    value = "1"
    apply_method = "pending-reboot"
  }
}
#############################################################################################################

#RDS subnet Group
resource "aws_db_subnet_group" "rds_subnet" {
  name        = "any-name"
  # count          = 2
  subnet_ids      = ["${aws_subnet.public_subnet[0].id}","${aws_subnet.public_subnet[1].id}"]

  tags = {
    Name = "My DB subnet group"
  }
}


#############################################################################################################

#EC2 instance
# resource "aws_instance" "webapp" {
#   instance_type = "${var.instance_type}"
#   ami           = var.image_id
#   vpc_security_group_ids = ["${aws_security_group.application.id}"]
#   subnet_id = "${aws_subnet.public_subnet[2].id}"
#   key_name = "${var.my_key}"
#   depends_on = [aws_db_instance.myRDSinstance]
#   iam_instance_profile = "${aws_iam_instance_profile.ec2_profile.name}"
#   user_data = <<-EOF
#               #!/bin/bash
#               sudo echo export "Bucketname=${aws_s3_bucket.my_s3_bucket_resource.bucket}" >> /etc/environment
#               sudo echo export "DBhost=${aws_db_instance.myRDSinstance.address}" >> /etc/environment
#               sudo echo export "DBendpoint=${aws_db_instance.myRDSinstance.endpoint}" >> /etc/environment
#               sudo echo export "DBname=${var.name}" >> /etc/environment
#               sudo echo export "DBusername=${aws_db_instance.myRDSinstance.username}" >> /etc/environment
#               sudo echo export "DBpassword=${aws_db_instance.myRDSinstance.password}" >> /etc/environment
#               EOF

#   root_block_device {
#     volume_size           = "${var.EC2_ROOT_VOLUME_SIZE}"
#     volume_type           = "${var.EC2_ROOT_VOLUME_TYPE}"
   
#   }

#   tags ={
#     Name= "Ec2 instance"
#     deploy = "codeDeploy"
#   } 



# }


#############################################################################################################

#IAM INSTANCE Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "CodeDeployEC2ServiceRole"
  role = "${aws_iam_role.ec2_role.name}"
}

#############################################################################################################
# Ec2 IAM Role
resource "aws_iam_role" "ec2_role" {
  name = "EC2-CSYE6225"

    assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com",
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "EC2-CSYE6225"
  }
}


#############################################################################################################

#CloudWatchAgentServerPolicy policy attachment to Role

resource "aws_iam_role_policy_attachment" "CloudWatchAgentServerPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = "${aws_iam_role.ec2_role.name}"
}


#############################################################################################################

#AmazonSSMManagedInstanceCore policy attachment to Role

resource "aws_iam_role_policy_attachment" "AmazonSSMManagedInstanceCore" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = "${aws_iam_role.ec2_role.name}"
}




#############################################################################################################

#AWS S3 policy
resource "aws_iam_role_policy" "policy" {
  name        = "S3Policy"
  role = "${aws_iam_role.ec2_role.id}"
  

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetBucketPolicy",
                "s3:PutBucketPolicy",
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:DeleteObject"
                
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.my_bucket}",
                "arn:aws:s3:::${var.my_bucket}/*"
            ]
        }
    ]
}
EOF
}

#############################################################################################################

# Code Deploy EC2-S3 policy
resource "aws_iam_role_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  role        = "${aws_iam_role.ec2_role.id}"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.codedeploybucket}",
                "arn:aws:s3:::${var.codedeploybucket}/*"
              ]
        }
    ]
}
EOF

}


#############################################################################################################

# CircleCI S3 Upload policy
resource "aws_iam_policy" "CircleCI-Upload-To-S3" {
  name        = "CircleCI-Upload-To-S3"
  description = "CircleCI-Upload-To-S3 policy"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": [
                "arn:aws:s3:::${var.codedeploybucket}",
                "arn:aws:s3:::${var.codedeploybucket}/*"
            ]
        }
    ]
}
EOF

}


resource "aws_iam_user_policy_attachment" "CircleCI-Upload-To-S3-attachment" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.CircleCI-Upload-To-S3.arn}"
}


#############################################################################################################
#CircleCI-Code-Deploy

resource "aws_iam_policy" "CircleCI-Code-Deploy" {
  name        = "CircleCI-Code-Deploy"
  description = "CircleCI-Code-Deploy policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.aws_account_id}:application:${var.application_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.aws_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${var.aws_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${var.aws_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF

}

resource "aws_iam_user_policy_attachment" "CircleCI-Code-Deploy-attachment" {
  user       = var.cicd
  policy_arn = "${aws_iam_policy.CircleCI-Code-Deploy.arn}"
}

#############################################################################################################


resource "aws_iam_user_policy_attachment" "circleci-ec2-ami-attachment" {
  user       = var.cicd
  policy_arn = "arn:aws:iam::${var.aws_account_id}:policy/circleci-ec2-ami"
}

#############################################################################################################

# CodeDeploy IAM Role
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

    assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

  tags = {
    tag-key = "CodeDeployServiceRole"
  }
}

#############################################################################################################

#AWSCodeDeployRole policy attachment to Role

resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
}


#############################################################################################################

#Code DEploy application
resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = var.application_name
}


# Deploymnet group
resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = var.deployment_group
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
 
  deployment_config_name = "CodeDeployDefault.AllAtOnce" # AWS defined deployment config

#  ec2_tag_set {
#     ec2_tag_filter {
#       key   = "Name"
#       type  = "KEY_AND_VALUE"
#       value = "Ec2 instance"
#     }

  # }
  autoscaling_groups = ["${aws_autoscaling_group.my_asg.id}"]
  # trigger a rollback on deployment failure event
  auto_rollback_configuration {
    enabled = true
    events = [
      "DEPLOYMENT_FAILURE",
    ]
  }
}





# resource "aws_instance" "webapp" {
#   instance_type = "${var.instance_type}"
#   ami           = var.image_id
#   vpc_security_group_ids = ["${aws_security_group.application.id}"]
#   subnet_id = "${aws_subnet.public_subnet[2].id}"
#   key_name = "${var.my_key}"
#   depends_on = [aws_db_instance.myRDSinstance]
#   iam_instance_profile = "${aws_iam_instance_profile.ec2_profile.name}"
#   user_data = <<-EOF
#               #!/bin/bash
#               sudo echo export "Bucketname=${aws_s3_bucket.my_s3_bucket_resource.bucket}" >> /etc/environment
#               sudo echo export "DBhost=${aws_db_instance.myRDSinstance.address}" >> /etc/environment
#               sudo echo export "DBendpoint=${aws_db_instance.myRDSinstance.endpoint}" >> /etc/environment
#               sudo echo export "DBname=${var.name}" >> /etc/environment
#               sudo echo export "DBusername=${aws_db_instance.myRDSinstance.username}" >> /etc/environment
#               sudo echo export "DBpassword=${aws_db_instance.myRDSinstance.password}" >> /etc/environment
#               EOF

#   root_block_device {
#     volume_size           = "${var.EC2_ROOT_VOLUME_SIZE}"
#     volume_type           = "${var.EC2_ROOT_VOLUME_TYPE}"
   
#   }

#   tags ={
#     Name= "Ec2 instance"
#     deploy = "codeDeploy"
#   } 



# }

# Autoscaling Launch Configuration

resource "aws_launch_configuration" "asg_launch_config" {
  name          = "asg_launch_config"
  image_id      = var.image_id
  instance_type = "t2.micro"
  associate_public_ip_address = true
  key_name = "${var.my_key}"
  iam_instance_profile = "${aws_iam_instance_profile.ec2_profile.name}"
  security_groups = ["${aws_security_group.application.id}"]

  user_data = <<-EOF
               #!/bin/bash
               sudo echo export "Bucketname=${aws_s3_bucket.my_s3_bucket_resource.bucket}" >> /etc/environment
               sudo echo export "DBhost=${aws_db_instance.myRDSinstance.address}" >> /etc/environment
               sudo echo export "DBendpoint=${aws_db_instance.myRDSinstance.endpoint}" >> /etc/environment
               sudo echo export "DBname=${var.name}" >> /etc/environment
               sudo echo export "DBusername=${aws_db_instance.myRDSinstance.username}" >> /etc/environment
               sudo echo export "DBpassword=${aws_db_instance.myRDSinstance.password}" >> /etc/environment
               sudo echo export "DomainName=${var.domain_name}" >> /etc/environment
               sudo echo export "TopicARN=${aws_sns_topic.password_reset.arn}" >> /etc/environment
               EOF
  root_block_device {
    volume_size           = "${var.EC2_ROOT_VOLUME_SIZE}"
    volume_type           = "${var.EC2_ROOT_VOLUME_TYPE}"
   
  }


}

# AWS AutoScaling group

resource "aws_autoscaling_group" "my_asg" {
    
    name = "my_asg"
    max_size = 5
    min_size = 2
    default_cooldown = 60
    desired_capacity = 2
    launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
    vpc_zone_identifier  = ["${aws_subnet.public_subnet[0].id}","${aws_subnet.public_subnet[1].id}","${aws_subnet.public_subnet[2].id}"]


    tag {
      key   = "Name"
      value = "Ec2 instance"
      propagate_at_launch = true
  } 
} 

# Scale up policy
resource "aws_autoscaling_policy" "instance_scale_up" {
    name = "instance_scale_up"
    scaling_adjustment = 1
    adjustment_type = "ChangeInCapacity"
    cooldown = 60
    autoscaling_group_name = "${aws_autoscaling_group.my_asg.name}"
}

#scale down policy

resource "aws_autoscaling_policy" "instance_scale_down" {
    name = "instance_scale_down"
    scaling_adjustment = -1
    adjustment_type = "ChangeInCapacity"
    cooldown = 60
    autoscaling_group_name = "${aws_autoscaling_group.my_asg.name}"
}


#CPU high policy
resource "aws_cloudwatch_metric_alarm" "CPU-high" {
    alarm_name = "cpu-util-high-agents"
    comparison_operator = "GreaterThanThreshold"
    evaluation_periods = "2"
    metric_name = "CPUUtilization"
    namespace = "AWS/EC2"
    period = "60"
    statistic = "Average"
    threshold = "50"
    alarm_description = "Scale-up if CPU > 50% for 2 minutes"
    alarm_actions = [
        "${aws_autoscaling_policy.instance_scale_up.arn}"
    ]
    dimensions = {
        AutoScalingGroupName = "${aws_autoscaling_group.my_asg.name}"
    }
}

#CPU low policy
resource "aws_cloudwatch_metric_alarm" "CPU-low" {
    alarm_name = "cpu-util-low-agents"
    comparison_operator = "LessThanThreshold"
    evaluation_periods = "2"
    metric_name = "CPUUtilization"
    namespace = "AWS/EC2"
    period = "60"
    statistic = "Average"
    threshold = "20"
    alarm_description = "Scale-down if CPU < 20% for 2 minutes"
    alarm_actions = [
        "${aws_autoscaling_policy.instance_scale_down.arn}"
    ]
    dimensions = {
        AutoScalingGroupName = "${aws_autoscaling_group.my_asg.name}"
    }
}

# Taget Group
resource "aws_lb_target_group" "alb-target-group" {
  name        = "alb-target-group"
  port        = 3000
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = "${aws_vpc.main.id}"
  deregistration_delay = 20

  stickiness {
    type = "lb_cookie"
    enabled = true
  }

    health_check {
    interval            = 15
    path                = "/"
    protocol            = "HTTP"
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher = "200"
  }

}


# Application load balancer
resource "aws_lb" "application_load_balancer" {
  name     = "application-load-balancer"
  internal = false
  load_balancer_type = "application"
  ip_address_type    = "ipv4"
  security_groups = ["${aws_security_group.loadBalancer.id}"]
  subnets = ["${aws_subnet.public_subnet[0].id}","${aws_subnet.public_subnet[1].id}","${aws_subnet.public_subnet[2].id}"]

  tags = {
    Name = "application-load-balancer"
  }

}

# alb listener
resource "aws_lb_listener" "alb-listner" {
  load_balancer_arn = "${aws_lb.application_load_balancer.arn}"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:318863692788:certificate/82856a52-e92d-4648-859f-5f73d533ce30"


  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.alb-target-group.arn}"
  }
}

resource "aws_autoscaling_attachment" "asg_attachment_bar" {
  autoscaling_group_name = "${aws_autoscaling_group.my_asg.id}"
  alb_target_group_arn   = "${aws_lb_target_group.alb-target-group.arn}"
}

  # ssl_policy        = "ELBSecurityPolicy-2016-08"
  # certificate_arn   = "arn:aws:acm:us-east-1:318863692788:certificate/82856a52-e92d-4648-859f-5f73d533ce30"

#Route53 record
resource "aws_route53_record" "alias_route53_record" {
  zone_id = "Z00457662L9DGICJLXDIJ" # Replace with your zone ID
  name    = var.domain_name # Replace with your name/domain/subdomain
  type    = "A"

  alias {
    name                   = "${aws_lb.application_load_balancer.dns_name}"
    zone_id                = "${aws_lb.application_load_balancer.zone_id}"
    evaluate_target_health = true
  }
}

#############################################################################################################

#Dynamo db table
resource "aws_dynamodb_table" "basic-dynamodb-table" {
  name           = var.DYNAMO_NAME
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "email_id"
 

  attribute {
    name = "email_id"
    type = "S"
  }


   ttl {
    attribute_name = "TimeToExist"
    enabled        = true
  }


  tags = {
    Name        = "dynamodb-table-1"
    Environment = "production"
  }
}

#Lambda IAM Role
resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
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


#AWSLambdaBasicExecutionRole policy attachment to Role

resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}

#AmazonSESFullAccess policy attachment to Role

resource "aws_iam_role_policy_attachment" "AmazonSESFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}

#AmazonDynamoDBFullAccess policy attachment to Role

resource "aws_iam_role_policy_attachment" "AmazonDynamoDBFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}



#Lambda Function
resource "aws_lambda_function" "my_lambda" {
  filename      = "/home/viraj/serverless/test_lambda2.zip"
  function_name = "Email_Service"
  role          = "${aws_iam_role.iam_for_lambda.arn}"
  handler       = "test.emailService"

  runtime = "nodejs12.x"

  environment {
    variables = {
      Domain_Name = var.domain_name
    }
  }
}

#Lambda SNS Permission
resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.my_lambda.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.password_reset.arn}"
}

#SNS TOPIC
resource "aws_sns_topic" "password_reset" {
  name = "password_reset"
}


resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = "${aws_sns_topic.password_reset.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.my_lambda.arn}"
}


#SNS policy
resource "aws_iam_policy" "SNS_topic_policy" {
  name        = "SNS_topic_policy"
  description = "SNS_topic_policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": 
   [
     {
      "Effect":"Allow",
      "Action":[
          "SNS:Subscribe",
          "SNS:SetTopicAttributes",
          "SNS:RemovePermission",
          "SNS:Receive",
          "SNS:Publish",
          "SNS:ListSubscriptionsByTopic",
          "SNS:GetTopicAttributes",
          "SNS:DeleteTopic",
          "SNS:AddPermission"
      ],
      "Resource":"${aws_sns_topic.password_reset.arn}"
     }
    ]
}
EOF

}



#Attaching SNS Topic Policy to Ec2 role
resource "aws_iam_role_policy_attachment" "snsTopicPolicy" {
  policy_arn = "${aws_iam_policy.SNS_topic_policy.arn}"
  role       = "${aws_iam_role.ec2_role.name}"
}



# resource "aws_iam_policy" "LambdaExecution" {
#   name        = "LambdaExecution"
#   description = "LambdaExecution"
#   policy      = <<EOF
#       {
#         "Version": "2012-10-17",
#         "Statement": 
#          [
#            {
#             "Effect": "Allow",
#             "Action": [
#                 "lambda:*"
#           ],
#             "Resource": [
#               "*"
#           ]
#             }
#         ]
#       }
# EOF

# }


resource "aws_iam_user_policy_attachment" "LambdaExecution-attachment" {
  user       = var.cicd
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}