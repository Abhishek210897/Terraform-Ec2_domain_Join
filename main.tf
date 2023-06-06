In this story, we will discuss two options to join an AWS EC2 instance to Active Directory (AD) using Terraform.

Using AWS Systems Manager (aka SSM), a small software component pre-installed almost all AWS AMIs.
Using a PowerShell Script on EC2 Instance bootstrapping, the process of passing user data to the Instance on the boot.
1) When Should I Use Using Option 1 or 2?
Using SSM is easy if we need to join the machine to the AD domain.

If we are going to execute a bootstrapping script to install and configure the EC2 Instance, the 2nd option is preferred. Just add the code at the end of our script.

For the PowerShell script, to keep the credentials secure, we will store the username and password in AWS Secret Manager

2) Using SSM to Join AD
The first step is to create a policy to attach to our EC2 Instance.

# IAM EC2 Policy with Assume Role 
 data "aws_iam_policy_document" "ec2_assume_role" {
   statement {
     actions = ["sts:AssumeRole"]
     principals {
       type        = "Service"
       identifiers = ["ec2.amazonaws.com"]
     }
   }
 }
# Create EC2 IAM Role
resource "aws_iam_role" "ec2_iam_role" {
   name                = "ec2-iam-role"
   path                = "/"
   assume_role_policy  = data.aws_iam_policy_document.ec2_assume_role.json
 }
# Create EC2 IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-profile"
  role = aws_iam_role.ec2_iam_role.name
}
# Attach Policies to Instance Role
resource "aws_iam_policy_attachment" "ec2_attach1" {
  name       = "ec2-iam-attachment"
  roles      = [aws_iam_role.ec2_iam_role.id]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_policy_attachment" "ec2_attach2" {
  name       = "ec2-iam-attachment"
  roles      = [aws_iam_role.ec2_iam_role.id]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}
Attach the join domain policy to the existing EC2 IAM Profile.

Note: In this example, we are using AWS Directory Service, however we can use AWS AD Connector or pass variables with the information required.

# Connect to AWS Directory Service
data "aws_directory_service_directory" "ad" {
  directory_id = var.directory_id
}
# AD Join 
resource "aws_ssm_document" "api_ad_join_domain" {
 name          = "ad-join-domain"
 document_type = "Command"
 content = jsonencode(
  {
    "schemaVersion" = "2.2"
    "description"   = "aws:domainJoin"
    "mainSteps" = [
      {
        "action" = "aws:domainJoin",
        "name"   = "domainJoin",
        "inputs" = {
          "directoryId": data.aws_directory_service_directory.ad.id,
          "directoryName" : data.aws_directory_service_directory.ad.name,
       "dnsIpAddresses" : sort(data.aws_directory_service_directory.ad.dns_ip_addresses)
          }
        }
      ]
    }
  )
}
# Associate Policy to Instance
resource "aws_ssm_association" "ad_join_domain_association" {
  depends_on = [ aws_instance.server ]
  name = aws_ssm_document.api_ad_join_domain.name
  targets {
    key    = "InstanceIds"
    values = [ aws_instance.server.id ]
  }
}
Then we create the EC2 Instance and will use the "iam_instance_profile" to pass the EC2 Instance profile allowed to join our AD.

resource "aws_instance" "server" {
  ami                         = data.aws_ami.windows-2022.id
  instance_type               = var.api_instance_size
  subnet_id                   = var.private_subnet_id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.server-sg.id]
  source_dest_check           = false
  key_name                    = aws_key_pair.key_pair.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.id
  # root disk
  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = var.root_volume_type
    delete_on_termination = true
  }
  tags = {
    Name        = var.server_name
    Environment = var.app_environment
    Owner       = var.app_owner
  }
  volume_tags = {
    Name        = var.server_name
    Environment = var.app_environment
    Owner       = var.app_owner
  }
}
3) Using PowerShell in a Bootstrapping Script to Join a Windows Instance to AD
In this example, we will read an AD account secret from AWS Secret Manager with a username and password to join the machine to the domain.

3.1) Requirements #1: Create a Secret in AWS Secret Manager
We will create one secret called "AD/ServiceAccounts/DomainJoin" and add the username and password of our service account to it.


3.2) Requirement #2: Attach an IAM Policy to the EC2 Instance to Access AWS Secret Manager
Create an EC2 IAM Policy

# IAM EC2 Policy with Assume Role 
 data "aws_iam_policy_document" "ec2_assume_role" {
   statement {
     actions = ["sts:AssumeRole"]
     principals {
       type        = "Service"
       identifiers = ["ec2.amazonaws.com"]
     }
   }
 }
# Create EC2 IAM Role
resource "aws_iam_role" "ec2_iam_role" {
   name                = "ec2-iam-role"
   path                = "/"
   assume_role_policy  = data.aws_iam_policy_document.ec2_assume_role.json
 }
# Create EC2 IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-profile"
  role = aws_iam_role.ec2_iam_role.name
}
# Attach Policies to Instance Role
resource "aws_iam_policy_attachment" "ec2_attach1" {
  name       = "ec2-iam-attachment"
  roles      = [aws_iam_role.ec2_iam_role.id]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_policy_attachment" "ec2_attach2" {
  name       = "ec2-iam-attachment"
  roles      = [aws_iam_role.ec2_iam_role.id]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}
attach the Secret Manager policy to the existing EC2 IAM Profile

# Create Secret Manager IAM Policy
resource "aws_iam_policy" "secret_manager_ec2_policy" {
  name        = "secret-manager-ec2-policy"
  description = "Secret Manager EC2 policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:*"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
# Attach Secret Manager Policies to Instance Role
resource "aws_iam_policy_attachment" "api_secret_manager_ec2_attach" {
  name       = "secret-manager-ec2-attachment"
  roles      = [aws_iam_role.ec2_iam_role.id]
  policy_arn = aws_iam_policy.secret_manager_ec2_policy.arn
}
3.3) Basic PowerShell Script to Read AD Account Secret and Join The EC2 Instance to AD
Below is our starting PowerShell code:

<powershell>
<# Install Dependencies #>;
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
Install-Module -Name AWS.Tools.Installer -Scope AllUsers -Force;
<# Define Variables #>;
$ad_secret_id = "AD/ServiceAccounts/DomainJoin";
$ad_domain = "kopicloud.local"
<# Read secret from the Secret Manager #>;
$secret_manager = Get-SECSecretValue -SecretId $ad_secret_id;
<# Convert the Secret JSON into an object #>;
$ad_secret = $secret_manager.SecretString | ConvertFrom-Json;
<# Set Credentials #>;
$username = $ad_secret.Username + "@" + $ad_domain;
$password = $ad_secret.Password | ConvertTo-SecureString -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential($username, $password);

<# Join AD Domain #>;
Add-Computer -DomainName $ad_domain -Credential $credential -Passthru -Verbose -Force -Restart;
</powershell>
3.4) Rename the EC2 Instance and Join the AD Domain
If we want to change the hostname and then join the machine, we will need to modify the previous PowerShell code a little bit:

<# Define Variables #>;
$ec2_name = "kopiweb1";
<# Rename Machine #>;
Rename-Computer -NewName $ec2_name -Force;
<# Join AD Domain #>;
Add-Computer -DomainName $ad_domain -Credential $credential -Options JoinWithNewName,AccountCreate -Force -Restart;
3.5) Read Instance Name from Metadata and Rename the EC2 Instance
We can read the instance name from the EC2 Instance tags and use this value to rename the machine; however, note to be able to read tags, we need to enable "instance_metadata_tags," which by default is disabled.

So, we need to modify the Terraform resource "aws_instance" and add the following code:

metadata_options {
  http_endpoint = "enabled"
  instance_metadata_tags = "enabled"
}
And then, we modify our PowerShell code to read tags:

<# Define Variables #>;
$ec2_name = Invoke-RestMethod -Method GET -Uri http://169.254.169.254/latest/meta-data/tags/instance/Name;
<# Rename Machine #>;
Rename-Computer -NewName $ec2_name -Force;
<# Join AD Domain #>;
Add-Computer -DomainName $ad_domain -Credential $credential -Options JoinWithNewName,AccountCreate -Force -Restart;
4) Terraform Code to Bootstrap a Windows EC2 Instance with PowerShell
First, we will add a Terraform data reference to our PowerShell script and pass the variables to it using "template_file":

# Bootstrapping PowerShell Script
data "template_file" "server" {
  template = file("${path.module}/join.ps1")
  vars = {
    ad_secret_id = "AD/ServiceAccounts/DomainJoin"
    ad_domain = "kopicloud.local"
  }
}
Create a PowerShell file called "join.ps1" and store it in the same folder of our Terraform files.

We will pass some variables, and to read the variable value; we will use the variable name inside brackets ${}.

<powershell>
<# Install Dependencies #>;
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force;
Install-Module -Name AWS.Tools.Installer -Scope AllUsers -Force;
<# Define Variables #>;
$ad_secret_id = "${ad_secret_id}";
$ad_domain = "${ad_domain}"
<# Read secret from the Secret Manager #>;
$secret_manager = Get-SECSecretValue -SecretId $ad_secret_id;
<# Convert the Secret JSON into an object #>;
$ad_secret = $secret_manager.SecretString | ConvertFrom-Json;
<# Set Credentials #>;
$username = $ad_secret.Username + "@" + $ad_domain;
$password = $ad_secret.Password | ConvertTo-SecureString -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential($username, $password);
<# Join AD Domain #>;
Add-Computer -DomainName $ad_domain -Credential $credential -Passthru -Verbose -Force -Restart;
</powershell>
And then, we create the EC2 Instance, using "user_data" to pass the PowerShell script and the "iam_instance_profile" to pass the EC2 Instance profile allowed to read AWS Secret Manager secrets.

resource "aws_instance" "server" {
  ami                         = data.aws_ami.windows-2022.id
  instance_type               = var.api_instance_size
  subnet_id                   = var.private_subnet_id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.server-sg.id]
  source_dest_check           = false
  key_name                    = aws_key_pair.key_pair.key_name
  user_data                   = data.template_file.server.rendered
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.id
  # root disk
  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = var.root_volume_type
    delete_on_termination = true
  }
  tags = {
    Name        = var.server_name
    Environment = var.app_environment
    Owner       = var.app_owner
  }
  volume_tags = {
    Name        = var.server_name
    Environment = var.app_environment
    Owner       = var.app_owner
  }
}
