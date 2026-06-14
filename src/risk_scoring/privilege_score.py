#!/usr/bin/env python3
"""
Privilege Risk Scoring Module
Analyzes IAM policies to determine how powerful a service account is

Author: Nathaniel Dadson
Independent Security Research
"""

import boto3
from typing import List, Dict, Set, Any, Tuple


class PrivilegeScorer:
    """
    Assigns a risk score (0-100) based on IAM policy permissions
    """
    
    HIGH_PRIVILEGE_ACTIONS = {
        'iam:CreateUser', 'iam:CreateRole', 'iam:CreatePolicy',
        'iam:AttachUserPolicy', 'iam:AttachRolePolicy',
        'iam:PutUserPolicy', 'iam:PutRolePolicy',
        'iam:CreateAccessKey', 'iam:DeleteAccessKey',
        'sts:AssumeRole', 'iam:PassRole',
        '*',
    }
    
    def __init__(self, profile_name: str = "service-account-governor"):
        self.session = boto3.Session(profile_name=profile_name)
        self.iam_client = self.session.client('iam')
        
    def get_attached_policies(self, role_name: str) -> List[Dict]:
        all_policies = []
        
        try:
            paginator = self.iam_client.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get('AttachedPolicies', []):
                    policy_arn = policy['PolicyArn']
                    policy_details = self.iam_client.get_policy(PolicyArn=policy_arn)
                    default_version = policy_details['Policy']['DefaultVersionId']
                    policy_version = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )
                    all_policies.append({
                        'name': policy['PolicyName'],
                        'type': 'managed',
                        'document': policy_version['PolicyVersion']['Document']
                    })
        except Exception as e:
            print(f"  Warning: {e}")
            
        return all_policies
    
    def extract_actions_from_policy(self, policy_document: Dict) -> Set[str]:
        actions = set()
        statements = policy_document.get('Statement', [])
        
        if not isinstance(statements, list):
            statements = [statements]
            
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            action = statement.get('Action', [])
            if isinstance(action, str):
                action = [action]
            for act in action:
                actions.add(act)
        return actions
    
    def calculate_privilege_score(self, role_name: str) -> Dict[str, Any]:
        print(f"  Analyzing: {role_name}")
        policies = self.get_attached_policies(role_name)
        
        if not policies:
            return {
                'role_name': role_name,
                'score': 0,
                'risk_level': 'MINIMAL',
                'findings': ['No policies attached'],
                'total_actions': 0,
                'policy_count': 0
            }
        
        all_actions = set()
        wildcard_action_found = False
        high_privilege_actions_found = set()
        
        for policy in policies:
            actions = self.extract_actions_from_policy(policy['document'])
            all_actions.update(actions)
            
            if '*' in actions:
                wildcard_action_found = True
            
            for high_act in self.HIGH_PRIVILEGE_ACTIONS:
                if high_act in actions:
                    high_privilege_actions_found.add(high_act)
        
        score = 0
        findings = []
        
        if wildcard_action_found:
            score += 40
            findings.append("Wildcard action '*' found")
        
        high_priv_count = len(high_privilege_actions_found)
        score += min(high_priv_count * 10, 30)
        if high_priv_count > 0:
            findings.append(f"{high_priv_count} high-privilege action(s)")
        
        policy_count = len(policies)
        score += min(policy_count, 10)
        
        score = min(score, 100)
        
        if score >= 80:
            risk_level = "CRITICAL"
        elif score >= 60:
            risk_level = "HIGH"
        elif score >= 40:
            risk_level = "MEDIUM"
        elif score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
            
        return {
            'role_name': role_name,
            'score': score,
            'risk_level': risk_level,
            'findings': findings,
            'total_actions': len(all_actions),
            'policy_count': policy_count
        }


if __name__ == "__main__":
    print("=" * 60)
    print("Privilege Risk Scorer - Test Mode")
    print("=" * 60)
    
    scorer = PrivilegeScorer()
    test_role = "AWSServiceRoleForSupport"
    
    result = scorer.calculate_privilege_score(test_role)
    
    print(f"\nResults for {result['role_name']}:")
    print(f"  Score: {result['score']}/100")
    print(f"  Risk Level: {result['risk_level']}")
    print(f"  Total Actions: {result['total_actions']}")
    print(f"  Policy Count: {result['policy_count']}")
    if result['findings']:
        print(f"  Findings: {', '.join(result['findings'])}")
