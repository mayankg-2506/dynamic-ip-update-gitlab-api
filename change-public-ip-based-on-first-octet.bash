#!/bin/bash

set -e

echo "Enter the option to update Dynamic IP:"
echo "=> Web-and-App"
echo "=> DB"
read -p "Please enter the exact name of your choice (e.g., 'Web-and-App' or 'DB'): " user_response

# Fetch the current public IP

current_ip=$(curl -s http://checkip.amazonaws.com)
current_ip_first_octet=$(echo $current_ip | cut -d '.' -f 1)

# Assume role for temporary credentials
role_arn="arn:aws:iam::$USER_ID:role/AWSRole-EC2SecurityGroup-UpdateIP-assumerole"
session_name="UpdateSecurityGroupSession"
temp_credentials=$(aws sts assume-role --role-arn "$role_arn" --role-session-name "$session_name")

export AWS_ACCESS_KEY_ID=$(echo $temp_credentials | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $temp_credentials | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $temp_credentials | jq -r '.Credentials.SessionToken')

# Security group ID
security_group_id="$SG_APP"
security_group_db_id="$SG_DB"

# Describe the security group to get the current rules
current_rules=$(aws ec2 describe-security-groups --group-ids "$security_group_id")
current_rules_db=$(aws ec2 describe-security-groups --group-ids "$security_group_db_id")
# Extract the current IP range (assuming a specific format)

list_of_ip_range=$(echo $current_rules | jq -r '.SecurityGroups[].IpPermissions[].IpRanges[].CidrIp')
list_of_ip_range_db=$(echo $current_rules_db | jq -r '.SecurityGroups[].IpPermissions[].IpRanges[].CidrIp')


current_ip_range=$( echo "$list_of_ip_range" | grep "^$current_ip_first_octet" | sort | uniq )
current_ip_range_db=$( echo "$list_of_ip_range_db" | grep "^$current_ip_first_octet" | sort | uniq )


if [[ $user_response == "Web-and-App" ]]; then
  if [[ $current_ip_range == 203* ]]; then
       # Revoke the old rule
       aws ec2 revoke-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 22 --cidr "$current_ip_range" --output json | jq '{Return}' && echo "port 22 --revoked with old Dynamic IP"
       aws ec2 revoke-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3000 --cidr "$current_ip_range" --output json | jq '{Return}' && echo "port 3000 --revoked with old Dynamic IP"
       aws ec2 revoke-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3001 --cidr "$current_ip_range" --output json | jq '{Return}' && echo "port 3001 --revoked with old Dynamic IP"
       echo
       echo "all necessary ports are revoked with old Dynamic IP...."
    
       # Authorize the new rule with the current IP
       aws ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 22 --cidr "$current_ip/32" --output json | jq '{Return}' && echo "port 22 --updated with updated new Dynamic IP"
       aws ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3000 --cidr "$current_ip/32" --output json | jq '{Return}' && echo "port 3000 --updated with updated new Dynamic IP"
       aws ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3001 --cidr "$current_ip/32" --output json | jq '{Return}' && echo "port 3001 --updated with updated new Dynamic IP"
       echo 
       echo "all necessary ports are updated with new Dynamic IP...."

   elif [[ $current_ip_range == 122* || $current_ip_range == 182* || $current_ip_range == 27* ]]; then
    
       aws ec2 revoke-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3000 --cidr "$current_ip_range" --output json | jq '{Return}' && echo "port 3000 --revoked with old Dynamic IP"
       aws ec2 revoke-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3001 --cidr "$current_ip_range" --output json | jq '{Return}' && echo "port 3001 --revoked with old Dynamic IP"

       aws ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3000 --cidr "$current_ip/32" --output json | jq '{Return}' && echo "port 3000 --updated with updated new Dynamic IP"
       aws ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol tcp --port 3001 --cidr "$current_ip/32" --output json | jq '{Return}' && echo "port 3001 --updated with updated new Dynamic IP"
   fi

elif [[ $user_response == "DB" ]]; then
  
    if [[ $current_ip_range_db == 203* ]]; then
       # Revoke the old rule
       aws ec2 revoke-security-group-ingress --group-id "$security_group_db_id" --protocol tcp --port 1433 --cidr "$current_ip_range_db" --output json | jq '{Return}' && echo "port 1433 --revoked with old Dynamic IP"
       echo
       echo "all necessary ports are revoked with old Dynamic IP...."
    
       # Authorize the new rule with the current IP
       aws ec2 authorize-security-group-ingress --group-id "$security_group_db_id" --protocol tcp --port 1433 --cidr "$current_ip/32" --output json | jq '{Return}' && echo "port 1433 --updated with updated new Dynamic IP"
       echo 
       echo "all necessary ports are updated with new Dynamic IP...."

   elif [[ $current_ip_range_db == 122* || $current_ip_range_db == 182* || $current_ip_range_db == 27* ]]; then
    
       aws ec2 revoke-security-group-ingress --group-id "$security_group_db_id" --protocol tcp --port 1433 --cidr "$current_ip_range_db" --output json | jq '{Return}' && echo "port 1433 --revoked with old Dynamic IP"
       echo
       echo "all necessary ports are revoked with old Dynamic IP...."

       aws ec2 authorize-security-group-ingress --group-id "$security_group_db_id" --protocol tcp --port 1433 --cidr "$current_ip/32" --output json | jq '{Return}' && echo "port 1433 --updated with updated new Dynamic IP"
       echo
       echo "all necessary ports are updated with new Dynamic IP...."
       
   fi
fi
