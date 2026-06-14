# Service Account Governor

**AWS Service Account Risk Scoring & Remediation Engine**

*Research project by Nathaniel Dadson* | *Independent Security Research*

---

## Overview

**The Problem:** Enterprise AWS environments accumulate thousands of service accounts (Lambda roles, EC2 instance profiles, service-linked roles). No one knows which are still needed, which have excessive permissions, or which have been abandoned. Stale, over-privileged service accounts are a primary attack vector in cloud breaches.

**The Solution:** Service Account Governor automatically discovers all service accounts, analyzes their privilege levels, tracks usage patterns, and produces a prioritized risk score. Security teams can reduce attack surface by 60%+ within 90 days.

**This is not a commercial tool.** This is open-source research code built to demonstrate practical cloud security automation.

---

## Research Focus

This project explores three core problems in cloud security engineering:

| Problem | Approach | Outcome |
|---------|----------|---------|
| **Service account discovery** | IAM API enumeration + trust policy analysis | Complete inventory of all robot identities |
| **Privilege risk scoring** | Policy document analysis with weighted risk model | 0-100 score based on permissions |
| **Activity anomaly detection** | Last-used tracking + behavioral baselines | Identify abandoned/compromised accounts |

---

## Architecture
┌─────────────────────────────────────────────────────────────┐
│ AWS Account │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ IAM Roles│ │ Policies │ │ CloudTrail│ │
│ └────┬─────┘ └────┬─────┘ └─────┬────┘ │
└───────┼────────────┼──────────────┼────────────────────────┘
│ │ │
▼ ▼ ▼
┌─────────────────────────────────────────────────────────────┐
│ Service Account Governor │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Layer 1: Discovery │ │
│ │ - List all IAM roles │ │
│ │ - Filter by service principal (trust policy) │ │
│ │ - Classify by service type (Lambda, EC2, ECS, etc.) │ │
│ └─────────────────────────────────────────────────────┘ │
│ ▼ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Layer 2: Privilege Analysis │ │
│ │ - Extract attached/inline policies │ │
│ │ - Parse actions and resources │ │
│ │ - Identify wildcards and high-privilege actions │ │
│ │ - Calculate privilege score (0-100) │ │
│ └─────────────────────────────────────────────────────┘ │
│ ▼ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Layer 3: Activity Analysis │ │
│ │ - Check RoleLastUsed │ │
│ │ - Calculate days since last use │ │
│ │ - Generate abandonment risk score │ │
│ └─────────────────────────────────────────────────────┘ │
│ ▼ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Layer 4: Combined Risk Scoring │ │
│ │ - Weighted formula (privilege 50% + activity 35%) │ │
│ │ - Prioritized ranking │ │
│ │ - Actionable recommendations │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Outputs │
│ - CSV report with all findings │
│ - Console summary with top risks │
│ - Remediation recommendations │
└─────────────────────────────────────────────────────────────┘

text

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.9+ | [Download](https://www.python.org/downloads/) |
| AWS Account | Free tier | Personal sandbox only |
| AWS CLI | 2.x+ | [Install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| Git | Latest | [Download](https://git-scm.com/downloads) |

**AWS Permissions Required (read-only):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy"
      ],
      "Resource": "*"
    }
  ]
}
Installation
bash
# Clone the repository
git clone https://github.com/nathanieldadson/service-account-governor.git
cd service-account-governor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials (if not already done)
aws configure --profile service-account-governor
Usage
Quick Start
bash
# Run complete analysis
python src/combined_scorer.py
Expected Output
text
🚀 Starting comprehensive service account risk analysis
============================================================

📋 Step 1: Discovering service accounts...
📊 Found 12 total IAM roles
🔍 Found service account: LambdaBasicExecutionRole → lambda.amazonaws.com

📊 Step 2: Scoring service accounts...

============================================================
📈 RISK ANALYSIS SUMMARY
============================================================

Risk Distribution:
  CRITICAL: 0 roles
  HIGH: 0 roles
  MEDIUM: 1 roles
  LOW: 2 roles

🔴 TOP 5 RISKIEST SERVICE ACCOUNTS:

  1. LambdaBasicExecutionRole - Score: 15.0/100 (LOW)
     Service: lambda.amazonaws.com
     Privilege: 15 | Activity: 0
     Recommendation: Low risk - continue monitoring

💾 Results exported to risk_analysis_results.csv
Module-by-Module Execution
bash
# Just discovery (list all service accounts)
python -c "from discovery.find_service_roles import ServiceRoleDiscovery; d = ServiceRoleDiscovery(); print(d.discover_all_service_accounts())"

# Just privilege scoring for a specific role
python -c "from risk_scoring.privilege_score import PrivilegeScorer; p = PrivilegeScorer(); print(p.calculate_privilege_score('LambdaBasicExecutionRole'))"

# Just activity scoring for a specific role
python -c "from risk_scoring.activity_score import ActivityScorer; a = ActivityScorer(); print(a.calculate_activity_score('LambdaBasicExecutionRole'))"
Project Structure
text
service-account-governor/
│
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
│
├── src/
│   ├── discovery/
│   │   └── find_service_roles.py    # Service account discovery
│   │
│   ├── risk_scoring/
│   │   ├── privilege_score.py       # Privilege risk analysis
│   │   └── activity_score.py        # Activity/abandonment risk
│   │
│   └── combined_scorer.py           # Master orchestrator
│
├── tests/                       # Unit tests (coming in Phase 2)
├── outputs/                     # Generated reports
└── docs/                        # Documentation (coming in Phase 3)
Risk Scoring Methodology
Privilege Score (0-100) - 50% Weight
Factor	Weight	Description
Wildcard actions	40 pts	"Action": "*" grants all permissions
High-privilege actions	10 pts each (max 30)	iam:*, sts:AssumeRole, etc.
Wildcard resources	20 pts	"Resource": "*" grants access to all
Policy count	up to 10 pts	More policies = more complexity
Activity Score (0-100) - 35% Weight
Days Since Last Use	Score	Risk Level
0-30 days	0	Active
31-60 days	25	Low usage
61-90 days	50	Moderate
91-180 days	75	High
180+ days	100	Abandoned
Never used	100	Critical
Final Risk Level Classification
Score Range	Risk Level	Recommended Action
70-100	CRITICAL	Immediate review/deletion
50-69	HIGH	Review this week
30-49	MEDIUM	Next sprint
10-29	LOW	Monitor
0-9	MINIMAL	No action needed
Development Roadmap
Phase	Status	Deliverable
Phase 1: Discovery	✅ Complete	Service account inventory
Phase 2: Privilege Scoring	✅ Complete	Privilege risk scores
Phase 3: Activity Scoring	✅ Complete	Abandonment detection
Phase 4: Combined Scorer	✅ Complete	Unified risk ranking
Phase 5: Remediation Automation	🔄 In Progress	Jira/ServiceNow integration
Phase 6: ML Safe-to-Delete Model	📅 Planned	Predictive deletion safety
Phase 7: Attack Path Integration	📅 Planned	Toxic combination detection
Research Publications
This code supports the following research papers (in progress):

"From Least Privilege to Least Used: A Machine Learning Framework for Cloud IAM Entitlement Risk Scoring" (Q3 2026)

"Service Account Abandonment: Measuring the Machine Identity Attack Surface in Enterprise AWS" (Q4 2026)

Contributing
This is an independent research project. Not open for external contributions at this time.

License
MIT License - See LICENSE file for details.

text
MIT License

Copyright (c) 2026 Nathaniel Dadson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:
...
Disclaimer
This software is for research and educational purposes only.

Run in a personal AWS sandbox, never in production

The author is not responsible for any unintended modifications to AWS resources

This tool performs read-only operations by design

Always review recommendations before taking remediation action

Author
Nathaniel Dadson

Independent Security Researcher

Focus: AI for Cloud Security, CIEM, Cloud Detection & Response

GitHub: github.com/nathanieldadson

This research is conducted independently and does not represent the views of any employer.

Last Updated
June 2026

