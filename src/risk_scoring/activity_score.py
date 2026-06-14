#!/usr/bin/env python3
"""
Activity Risk Scoring Module - Identifies abandoned service accounts

Author: Nathaniel Dadson
Independent Security Research
"""

import boto3
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class ActivityScorer:
    def __init__(self, profile_name: str = "service-account-governor"):
        self.session = boto3.Session(profile_name=profile_name)
        self.iam_client = self.session.client('iam')
        
    def get_role_last_used(self, role_name: str) -> Optional[datetime]:
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            last_used = response['Role'].get('RoleLastUsed', {})
            return last_used.get('LastUsedDate')
        except Exception as e:
            print(f"  Warning: {e}")
            return None
    
    def calculate_activity_score(self, role_name: str) -> Dict[str, Any]:
        last_used = self.get_role_last_used(role_name)
        now = datetime.now(timezone.utc)
        
        if last_used is None:
            return {
                'role_name': role_name,
                'score': 100,
                'risk_level': 'CRITICAL',
                'days_unused': None,
                'status': 'NEVER_USED',
                'recommendation': 'Review immediately - may be unnecessary'
            }
        
        days_unused = (now - last_used).days
        
        if days_unused <= 30:
            score = 0
            risk_level = "ACTIVE"
            recommendation = "Recently used - keep monitoring"
        elif days_unused <= 60:
            score = 25
            risk_level = "LOW_USAGE"
            recommendation = "Used within 2 months - consider if still needed"
        elif days_unused <= 90:
            score = 50
            risk_level = "MODERATE"
            recommendation = "Not used in 3 months - review ownership"
        elif days_unused <= 180:
            score = 75
            risk_level = "HIGH"
            recommendation = "Not used in 6 months - candidate for deletion"
        else:
            score = 100
            risk_level = "CRITICAL"
            recommendation = "Abandoned (>6 months) - delete immediately"
            
        return {
            'role_name': role_name,
            'score': score,
            'risk_level': risk_level,
            'days_unused': days_unused,
            'last_used_date': last_used.isoformat(),
            'status': 'USED',
            'recommendation': recommendation
        }


if __name__ == "__main__":
    print("=" * 60)
    print("Activity Risk Scorer - Test Mode")
    print("=" * 60)
    
    scorer = ActivityScorer()
    
    for role in ["AWSServiceRoleForSupport", "AWSServiceRoleForTrustedAdvisor"]:
        result = scorer.calculate_activity_score(role)
        print(f"\n{result['role_name']}:")
        if result.get('days_unused'):
            print(f"  Days unused: {result['days_unused']}")
        else:
            print(f"  Never used")
        print(f"  Score: {result['score']}/100 ({result['risk_level']})")
        print(f"  Recommendation: {result['recommendation']}")
