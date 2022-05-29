resource "aws_instance" "ubuntu_server" {
  ami           = "ami-04505e74c0741db8d"
  instance_type = "t2.micro"
availability_zone= "us-east-1a"
key_name = aws_key_pair.ec2_key_pair.id
  tags = {
    Name = "ubuntu_server"
  }
}
resource "aws_vpc" "first-vpc" {
  cidr_block       = "10.0.0.0/16"
  

  tags = {
    Name = "first-vpc"
  }
}
resource "aws_subnet" "Subnet-1" {
  vpc_id     = aws_vpc.first-vpc.id
  cidr_block = "10.0.1.0/24"
availability_zone = "us-east-1a"
  tags = {
    Name = "Subnet-1"
  }
}
resource "aws_subnet" "Subnet-2" {
  vpc_id     = aws_vpc.first-vpc.id
  cidr_block = "10.0.2.0/24"
availability_zone = "us-east-1b"
  tags = {
    Name = "Subnet-2"
  }
}

resource "aws_subnet" "private-Subnet-1" {
  vpc_id     = aws_vpc.first-vpc.id
  cidr_block = "10.0.3.0/24"
availability_zone = "us-east-1a"
  tags = {
    Name = "private-Subnet-1"
  }
}

resource "aws_subnet" "private-Subnet-2" {
  vpc_id     = aws_vpc.first-vpc.id
  cidr_block = "10.0.4.0/24"
availability_zone = "us-east-1b"
  tags = {
    Name = "private-Subnet-2"
  }
}
resource "aws_subnet" "private-Subnet-3" {
  vpc_id     = aws_vpc.first-vpc.id
  cidr_block = "10.0.5.0/24"
availability_zone = "us-east-1a"
  tags = {
    Name = "private-Subnet-3"
  }
}
resource "aws_subnet" "private-Subnet-4" {
  vpc_id     = aws_vpc.first-vpc.id
  cidr_block = "10.0.6.0/24"
availability_zone = "us-east-1b"
  tags = {
    Name = "private-Subnet-4"
  }
}


resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.first-vpc.id

  tags = {
    Name = "internet-gatway"
  }
}

resource "aws_route_table" "public-route-table" {
  vpc_id = aws_vpc.first-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gateway.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table_association" "route-table-association-subnet_1" {
  subnet_id      = aws_subnet.Subnet-1.id
  route_table_id = aws_route_table.public-route-table.id
}

resource "aws_route_table_association" "route-table-association-subnet_2" {
  subnet_id      = aws_subnet.Subnet-2.id
  route_table_id = aws_route_table.public-route-table.id
}

resource "aws_security_group" "allow_web-traffic" {
  name        = "allow_web-traffic"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.first-vpc.id


  ingress {
    description      = "https from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    
  }
  ingress {
    description      = "http from VPC"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    
  }

  ingress {
    description      = "ssh from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

resource "aws_lb" "application_load_balancer" {
  name               = "apllication-lb-tf"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.allow_web-traffic.id]
  subnets            = [aws_subnet.Subnet-1.id ,aws_subnet.Subnet-2.id]

  enable_deletion_protection = false

  tags = {
    Environment = "application-load-balancer"
  }
}


resource "aws_lb_target_group" "application_lb_target_group" {
  name     = "application-lb-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.first-vpc.id

  health_check {
    healthy_threshold =5
    interval =30
    matcher ="200,302"
    path ="/"
    port ="traffic-port"
    protocol ="HTTP"
    timeout =5
    unhealthy_threshold =2
  }
}

resource "aws_lb_listener" "lb_front_end" {
  load_balancer_arn = aws_lb.application_load_balancer.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      host ="#{host}"
      path ="/#{path}"
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# resource "aws_lb_listener" "lb_listener_for_foward_action" {
  # load_balancer_arn = aws_lb.application_load_balancer.id
  # port              = "443"
 # protocol          = "HTTPS"
  # ssl_policy        = "ELBSecurityPolicy-2016-08"
 # certificate_arn = "arn:aws:acm:us-east-1:626178073386:certificate/3706b6b3-7f4f-47c5-85e7-25897a405a18"

  # default_action {
   # type             = "forward"
    #target_group_arn = aws_lb_target_group.application_lb_target_group.arn
 # }
#}


resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "ec2_key_pair"
  public_key = tls_private_key.rsa_key_pair.public_key_openssh
}

resource "tls_private_key" "rsa_key_pair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "local_file" "private_key_content" {
    content  = tls_private_key.rsa_key_pair.private_key_pem
    filename = "private_key_content"
}
resource "aws_launch_configuration" "autoscalling_launch_configurations" {
# Defining the name of the Autoscaling launch configuration
  name          = "autoscalling_launch_config"
# Defining the image ID of AWS EC2 instance
  image_id      = "ami-04505e74c0741db8d"
# Defining the instance type of the AWS EC2 instance
  instance_type = "t2.micro"
# Defining the Key that will be used to access the AWS EC2 instance
  key_name = aws_key_pair.ec2_key_pair.id
}

resource "aws_key_pair" "amazon_linux_key_pair" {
  key_name   = "amazon_linux_key_pair"
  public_key = tls_private_key.amazon_linux_rsa_key_pair.public_key_openssh
}

resource "tls_private_key" "amazon_linux_rsa_key_pair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "local_file" "amazon_linux_private_key_content" {
    content  = tls_private_key.amazon_linux_rsa_key_pair.private_key_pem
    filename = "amazon_linux_private_key_content"
}



# Creating the autoscaling group within us-east-1a availability zone
resource "aws_autoscaling_group" "autoscale_group" {
# Defining the availability Zone in which AWS EC2 instance will be launched
  availability_zones        = ["us-east-1a"]
# Specifying the name of the autoscaling group
  name                      = "autoscalling_group"
# Defining the maximum number of AWS EC2 instances while scaling
  max_size                  = 3
# Defining the minimum number of AWS EC2 instances while scaling
  min_size                  = 1
# Grace period is the time after which AWS EC2 instance comes into service before checking health.
  health_check_grace_period = 30
# The Autoscaling will happen based on health of AWS EC2 instance defined in AWS CLoudwatch Alarm 
  health_check_type         = "EC2"
# force_delete deletes the Auto Scaling Group without waiting for all instances in the pool to terminate
  force_delete              = true
# Defining the termination policy where the oldest instance will be replaced first 
  termination_policies      = ["OldestInstance"]
# Scaling group is dependent on autoscaling launch configuration because of AWS EC2 instance configurations
  launch_configuration      = aws_launch_configuration.autoscalling_launch_configurations.name
}
# Creating the autoscaling schedule of the autoscaling group

resource "aws_autoscaling_schedule" "autoscalling_group_schedule" {
  scheduled_action_name  = "autoscalegroup_action"
# The minimum size for the Auto Scaling group
  min_size               = 1
# The maxmimum size for the Auto Scaling group
  max_size               = 2
# Desired_capacity is the number of running EC2 instances in the Autoscaling group
  desired_capacity       = 1
# defining the start_time of autoscaling if you think traffic can peak at this time.
  start_time             = "2022-05-30T11:00:00Z"
  autoscaling_group_name = aws_autoscaling_group.autoscale_group.name
}

# Creating the autoscaling policy of the autoscaling group
resource "aws_autoscaling_policy" "autoscalling_group_policy" {
  name                   = "autoscale_group_policy"
# The number of instances by which to scale.
  scaling_adjustment     = 2
  adjustment_type        = "ChangeInCapacity"
# The amount of time (seconds) after a scaling completes and the next scaling starts.
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.autoscale_group.name
}
# Creating the AWS CLoudwatch Alarm that will autoscale the AWS EC2 instance based on CPU utilization.
resource "aws_cloudwatch_metric_alarm" "autoscalling_alarm" {
# defining the name of AWS cloudwatch alarm
  alarm_name = "autoscalling_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
# Defining the metric_name according to which scaling will happen (based on CPU) 
  metric_name = "CPUUtilization"
# The namespace for the alarm's associated metric
  namespace = "AWS/EC2"
# After AWS Cloudwatch Alarm is triggered, it will wait for 60 seconds and then autoscales
  period = "60"
  statistic = "Average"
# CPU Utilization threshold is set to 10 percent
  threshold = "10"
  alarm_actions = [
        "${aws_autoscaling_policy.autoscalling_group_policy.arn}"
    ]
dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.autoscale_group.name}"
  }
}

resource "aws_eip" "elastic_ip_for_natgatway_1" {
  vpc      = true
  tags = {
    name="elastic-ip-for-natgateway-1"
  }
}

resource "aws_eip" "elastic_ip_for_natgatway_2" {
  vpc      = true
  tags = {
    name="elastic-ip-for-natgateway-2"
  }
}

resource "aws_nat_gateway" "natgateway_1" {
  allocation_id = aws_eip.elastic_ip_for_natgatway_1.id
  subnet_id     = aws_subnet.Subnet-1.id

  tags = {
    Name = "natgateway-1"
  }
}

resource "aws_nat_gateway" "natgateway_2" {
  allocation_id = aws_eip.elastic_ip_for_natgatway_2.id
  subnet_id     = aws_subnet.Subnet-2.id

  tags = {
    Name = "natgateway-2"
  }
}

resource "aws_route_table" "private_subnet_route_table_1" {
  vpc_id = aws_vpc.first-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgateway_1.id
  }

  tags = {
    Name = "private-route-table-1"
  }
}
resource "aws_route_table_association" "private_route_table_association_1" {
  subnet_id      = aws_subnet.private-Subnet-1.id
  route_table_id = aws_route_table.private_subnet_route_table_1.id
}

resource "aws_route_table_association" "private_route_table_association_subnet_3" {
  subnet_id      = aws_subnet.private-Subnet-3.id
  route_table_id = aws_route_table.private_subnet_route_table_1.id
}

resource "aws_route_table" "private_subnet_route_table_2" {
  vpc_id = aws_vpc.first-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgateway_2.id
  }

  tags = {
    Name = "private-route-table-2"
  }
}

resource "aws_route_table_association" "private_route_table_association_2" {
  subnet_id      = aws_subnet.private-Subnet-2.id
  route_table_id = aws_route_table.private_subnet_route_table_2.id
}

resource "aws_route_table_association" "private_route_table_association_subnet_4" {
  subnet_id      = aws_subnet.private-Subnet-4.id
  route_table_id = aws_route_table.private_subnet_route_table_2.id
}

resource "aws_db_subnet_group" "database_subnet_group" {
  name       = "database-subnet-group"
  subnet_ids = [ aws_subnet.private-Subnet-3.id, aws_subnet.private-Subnet-4.id]
description = "subnet for the datebase instance, eg mysql"
  tags = {
    Name = "DB subnet group"
  }
}

resource "aws_db_instance" "database_instance" {
  allocated_storage = 12
  engine            = "mysql"
  engine_version    = "5.7"
  instance_class    = "db.t2.micro"
  db_name             = "mysql_database_instance"
  password          = "test1234"
  username          = "test1234"
  skip_final_snapshot = true
  availability_zone = "us-east-1a"
db_subnet_group_name = aws_db_subnet_group.database_subnet_group.name
multi_az = false
parameter_group_name = "default.mysql5.7"
}

resource "aws_instance" "amazon_linux_private_webserver_1" {
  ami           = "ami-0f9fc25dd2506cf6d"
  instance_type = "t2.micro"
subnet_id = aws_subnet.private-Subnet-1.id
vpc_security_group_ids = [ aws_security_group.allow_web-traffic.id ]
key_name = "${aws_key_pair.amazon_linux_key_pair.key_name}"
user_data =<<-EOF
#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
EOF


  tags = {
    Name = "HelloWorld"
  }
}

resource "aws_instance" "amazon_linux_private_webserver_2" {
  ami           = "ami-0f9fc25dd2506cf6d"
  instance_type = "t2.micro"
subnet_id = aws_subnet.private-Subnet-2.id 
vpc_security_group_ids = [ aws_security_group.allow_web-traffic.id ]
key_name = "${aws_key_pair.amazon_linux_key_pair.key_name}"
user_data =<<-EOF
#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
EOF

  tags = {
    Name = "HelloWorld"
  }
}

