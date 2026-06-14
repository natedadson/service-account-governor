#!/usr/bin/env python3
"""
Combined Risk Scorer - Integrates privilege + activity risk

Author: Nathaniel Dadson
Independent Security Research
"""

import sys
import csv
from typing import Dict, List, Any

sys.path.insert(0, '.')

from discovery.find_service_roles import ServiceRoleDiscovery
from risk_scoring.privilege_score import PrivilegeScorer
from risk_scoring.activity_score import ActivityScorer


class CombinedRiskScorer:
    def __init__(self, profile_name: str = "service-account-governor"):
        self.discovery = ServiceRoleDiscovery(profile_name)
        self.privilege_scorer = PrivilegeScorer(profile_name)
        self.activity_scorer = ActivityScorer(profile_name)
        
    def calculate_final_risk_score(self, role_name: str) -> Dict[str, Any]:
        privilege = self.privilege_scorer.calculate_privilege_score(role_name)
        activity = self.activity_scorer.calculate_activity_score(role_name)
        
        final_score = (privilege['score'] * 0.50) + (activity['score'] * 0.35)
        
        if final_score >= 70:
            overall_risk = "CRITICAL"
        elif final_score >= 50:
            overall_risk = "HIGH"
        elif final_score >= 30:
            overall_risk = "MEDIUM"
        elif final_score >= 10:
            overall_risk = "LOW"
        else:
            overall_risk = "MINIMAL"
            
        return {
            'role_name': role_name,
            'final_score': round(final_score, 1),
            'overall_risk': overall_risk,
            'privilege_score': privilege['score'],
            'privilege_risk': privilege['risk_level'],
            'activity_score': activity['score'],
            'activity_risk': activity['risk_level'],
            'days_unused': activity.get('days_unused'),
            'recommendation': activity['recommendation']
        }
    
    def analyze_all_service_accounts(self) -> List[Dict[str, Any]]:
        print("=" * 70)
        print("Service Account Governor - Complete Risk Analysis")
        print("=" * 70)
        
        service_accounts = self.discovery.discover_all_service_accounts()
        
        if not service_accounts:
            print("No service accounts found")
            return []
        
        print(f"\nScoring {len(service_accounts)} service accounts...")
        results = []
        
        for account in service_accounts:
            role_name = account['role_name']
            print(f"\nAnalyzing: {role_name}")
            
            try:
                risk_result = self.calculate_final_risk_score(role_name)
                risk_result['service_principal'] = account['service_principal']
                risk_result['service_type'] = account['service_type']
                results.append(risk_result)
            except Exception as e:
                print(f"  Error: {e}")
        
        results.sort(key=lambda x: x['final_score'], reverse=True)
        self.print_summary(results)
        return results
    
    def print_summary(self, results: List[Dict]):
        print("\n" + "=" * 70)
        print("RISK ANALYSIS SUMMARY")
        print("=" * 70)
        
        print("\nTop Riskiest Service Accounts:")
        for idx, result in enumerate(results[:5], 1):
            print(f"\n{idx}. {result['role_name']}")
            print(f"   Final Score: {result['final_score']}/100 ({result['overall_risk']})")
            print(f"   Privilege: {result['privilege_score']} | Activity: {result['activity_score']}")
            print(f"   Recommendation: {result['recommendation']}")
    
    def export_results(self, results: List[Dict], filename: str = "risk_analysis_results.csv"):
        if not results:
            return
        
        with open(filename, 'w', newline='') as f:
            fieldnames = ['role_name', 'final_score', 'overall_risk', 
                         'privilege_score', 'activity_score', 'days_unused',
                         'service_principal', 'service_type', 'recommendation']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                row = {k: result.get(k, '') for k in fieldnames}
                writer.writerow(row)
        
        print(f"\nExported to {filename}")


if __name__ == "__main__":
    scorer = CombinedRiskScorer()
    results = scorer.analyze_all_service_accounts()
    
    if results:
        scorer.export_results(results)
        print("\nAnalysis complete!")
