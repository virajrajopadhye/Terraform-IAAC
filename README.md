# AWS VPC Terraform module
This terraform template creates infrastructure necessary to run the complete nodejs application

## Resources created

## VPC
## Subnets
## Routing Table
## Security Group
## Internet Gateway
## Route table Association
## Load Balancer
## Auto Scaling Group
## Lambda function
## DB instance


How to use this file?
Install AWS CLI
Set up your AWS CLI user profile (for eg: to check type in console: export AWS_PROFILE="profile name")
Run 'terraform init'
Run 'terraform plan'
Run 'terraform apply'

## For importing SSL certificate to AWS ACM use following command
aws acm import-certificate --certificate fileb://prod_virajrajopadhye_me.crt --private-key fileb://SslCsrViraj.key --certificate-chain fileb://prod_virajrajopadhye.ca-bundle
(P.S set up the AWS_PROFILE before running this command and replace .crt, .ca-bundle and .key files with your own)

It should create A VPC with a public route table with 3 public subnets associated to it, an Internet Gateway and a security group with access to port 443, 22, 80.
