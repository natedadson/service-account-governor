#!/usr/bin/env python3
"""
Service Account Discovery Module
Finds all IAM roles that can be assumed by AWS services (not humans)

Author: Nathaniel Dadson
Independent Security Research
"""

import boto3
import csv
from datetime import datetime
from typing import List, Dict, Any, Tuple


class ServiceRoleDiscovery:
    """
    Discovers and classifies service accounts (IAM roles used by AWS services)
    
    A service account is an IAM role that AWS services (like Lambda, EC2, ECS)
    can assume, rather than a human user. These are often over-permissioned
    and forgotten, creating security risk.
    """
    
    def __init__(self, profile_name: str = "service-account-governor"):
        """
        Initialize AWS session with a named profile
        
        Args:
            profile_name: AWS CLI profile name (created with 'aws configure --profile name')
        """
        self.session = boto3.Session(profile_name=profile_name)
        self.iam_client = self.session.client('iam')
        
    def list_all_roles(self) -> List[Dict[str, Any]]:
        """
        Fetch ALL IAM roles in the AWS account
        
        Uses paginator to handle AWS's API limits (1000 roles per page)
        
        Returns:
            List of role dictionaries from AWS IAM API
        """
        all_roles = []
        paginator = self.iam_client.get_paginator('list_roles')
        
        for page in paginator.paginate():
            all_roles.extend(page['Roles'])
            
        print(f"📊 Found {len(all_roles)} total IAM roles")
        return all_roles
    
    def is_service_account(self, role: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Determine if a role is a service account (robot) vs human role
        
        How it works: 
        - Service accounts have trust policies with Principal.Service
        - Human roles have Principal.AWS (specific users/accounts)
        
        Example service account trust policy:
        {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        
        Args:
            role: IAM role dictionary from AWS API
            
        Returns:
            Tuple of (is_service_account, identifier)
            - is_service_account: True if this is a service account
            - identifier: The service name (e.g., "lambda.amazonaws.com") or reason
        """
        assume_role_policy = role.get('AssumeRolePolicyDocument', {})
        statements = assume_role_policy.get('Statement', [])
        
        # Handle case where Statement is a dict, not a list
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            principal = statement.get('Principal', {})
            
            # Check if Principal is an AWS Service (the key indicator)
            if 'Service' in principal:
                service_names = principal['Service']
                if isinstance(service_names, list):
                    service = ", ".join(service_names)
                else:
                    service = service_names
                return True, service
                
            # Also capture cross-account roles for awareness
            if 'AWS' in principal and '*' not in str(principal['AWS']):
                return False, "cross_account_human"
                
        return False, "human_or_unknown"
    
    def classify_service_account_type(self, service_name: str) -> str:
        """
        Categorize the service account by AWS service type
        
        Different services have different risk profiles:
        - Lambda: Short-lived, but can have broad permissions
        - EC2: Persistent, higher risk if compromised
        - RDS: Database access, sensitive data risk
        
        Args:
            service_name: The AWS service principal (e.g., "lambda.amazonaws.com")
            
        Returns:
            Category string: serverless_function, compute_instance, container,
            storage, database, ci_cd, infrastructure, or other_service
        """
        service_map = {
            'lambda': 'serverless_function',
            'ec2': 'compute_instance',
            'ecs': 'container',
            'eks': 'kubernetes',
            's3': 'storage',
            'rds': 'database',
            'codebuild': 'ci_cd',
            'cloudformation': 'infrastructure',
            'support': 'aws_support',
            'trustedadvisor': 'aws_support',
        }
        
        for key, category in service_map.items():
            if key in service_name.lower():
                return category
        return 'other_service'

    def discover_all_service_accounts(self) -> List[Dict[str, Any]]:
        """
        Main orchestration method - find and classify all service accounts
        
        Returns:
            List of dictionaries, each containing:
            - role_name: Name of the IAM role
            - role_arn: AWS Resource Name
            - service_principal: Which AWS service assumes this role
            - service_type: Categorized service type
            - created_date: When the role was created
            - role_id: Unique role identifier
            - path: IAM path (for organization)
        """
        print("\n🔍 Discovering service accounts...")
        all_roles = self.list_all_roles()
        service_accounts = []
        
        for role in all_roles:
            is_service, service_principal = self.is_service_account(role)
            
            if is_service:
                account_info = {
                    'role_name': role['RoleName'],
                    'role_arn': role['Arn'],
                    'service_principal': service_principal,
                    'service_type': self.classify_service_account_type(service_principal),
                    'created_date': role['CreateDate'],
                    'role_id': role['RoleId'],
                    'path': role.get('Path', '/'),
                }
                service_accounts.append(account_info)
                print(f"  ✓ {role['RoleName']} → {service_principal}")
                
        print(f"\n✅ Total service accounts discovered: {len(service_accounts)}")
        return service_accounts

    def export_to_csv(self, service_accounts: List[Dict[str, Any]], filename: str = "service_accounts.csv"):
        """
        Export findings to CSV for analysis in Excel, pandas, or other tools
        
        Args:
            service_accounts: List of service account dictionaries
            filename: Output CSV filename
        """
        if not service_accounts:
            print("⚠️ No service accounts to export")
            return
        
        # Handle datetime serialization for CSV
        def prepare_for_csv(item: Dict) -> Dict:
            prepared = {}
            for key, value in item.items():
                if isinstance(value, datetime):
                    prepared[key] = value.isoformat()
                else:
                    prepared[key] = value
            return prepared
        
        keys = list(prepare_for_csv(service_accounts[0]).keys())
        with open(filename, 'w', newline='') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            for account in service_accounts:
                dict_writer.writerow(prepare_for_csv(account))
                
        print(f"💾 Exported {len(service_accounts)} service accounts to {filename}")
    
    def print_summary(self, service_accounts: List[Dict[str, Any]]):
        """
        Print a human-readable summary of discovered service accounts
        """
        if not service_accounts:
            print("No service accounts found.")
            return
            
        # Count by service type
        type_counts = {}
        for account in service_accounts:
            stype = account['service_type']
            type_counts[stype] = type_counts.get(stype, 0) + 1
            
        print("\n📊 Service Account Summary by Type:")
        for stype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {stype}: {count}")
            
        # Show the 5 oldest service accounts (potential cleanup candidates)
        oldest = sorted(service_accounts, key=lambda x: x['created_date'])[:5]
        print("\n📅 5 Oldest Service Accounts (potential cleanup candidates):")
        for account in oldest:
            days_old = (datetime.now(account['created_date'].tzinfo) - account['created_date']).days
            print(f"  {account['role_name']} - Created {days_old} days ago - {account['service_principal']}")


# Run this if executed directly
if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Service Account Discovery Tool")
    print("=" * 60)
    print("Author: Nathaniel Dadson (Independent Security Research)")
    print("=" * 60)
    
    try:
        discoverer = ServiceRoleDiscovery()
        service_accounts = discoverer.discover_all_service_accounts()
        
        if service_accounts:
            discoverer.print_summary(service_accounts)
            discoverer.export_to_csv(service_accounts)
            print(f"\n✨ Discovery complete! Check service_accounts.csv for full data.")
        else:
            print("\n⚠️ No service accounts found. Make sure your AWS profile has permissions.")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("1. Run: aws configure --profile service-account-governor")
        print("2. Verify your AWS credentials are correct")
        print("3. Check that your IAM user has iam:ListRoles permission")
