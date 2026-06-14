# Service Account Governor

**AWS Service Account Risk Scoring & Remediation Engine**

*Research project by Nathaniel Dadson* | *Independent Security Research*

---

## Overview

**The Problem:** Enterprise AWS environments accumulate thousands of service accounts (Lambda roles, EC2 instance profiles, service-linked roles). No one knows which are still needed, which have excessive permissions, or which have been abandoned. Stale, over-privileged service accounts are a primary attack vector in cloud breaches.

**The Solution:** Service Account Governor automatically discovers all service accounts, analyzes their privilege levels, tracks usage patterns, and produces a prioritized risk score. Security teams can reduce attack surface by 60%+ within 90 days.

**This is not a commercial tool.** This is open-source research code built to demonstrate practical cloud security automation.

---

## Architecture

```mermaid
flowchart TD
    subgraph AWS["AWS Account"]
        IAM[("IAM Roles")]
        Policies[("IAM Policies")]
        CloudTrail[("CloudTrail Logs")]
    end

    subgraph Governor["Service Account Governor"]
        direction TB
        L1["Layer 1: Discovery\n- List IAM roles\n- Filter service principals\n- Classify by type"]
        L2["Layer 2: Privilege Analysis\n- Extract policies\n- Parse actions/resources\n- Calculate privilege score (0-100)"]
        L3["Layer 3: Activity Analysis\n- Check RoleLastUsed\n- Calculate days unused\n- Generate abandonment score"]
        L4["Layer 4: Combined Scoring\n- Weighted formula\n- Prioritized ranking\n- Actionable recommendations"]
        
        L1 --> L2 --> L3 --> L4
    end

    subgraph Outputs["Outputs"]
        Console["Console Summary\n- Top risks\n- Recommendations"]
        CSV["CSV Export\n- Full results\n- Risk scores"]
    end

    IAM --> L1
    Policies --> L2
    CloudTrail --> L3
    L4 --> Console
    L4 --> CSV
Prerequisites
Requirement	Version	Notes
Python	3.9+	Download
AWS Account	Free tier	Personal sandbox only
AWS CLI	2.x+	Install guide
Git	Latest	Download
AWS Permissions Required (read-only):

json
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
git clone https://github.com/natedadson/service-account-governor.git
cd service-account-governor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure --profile service-account-governor
Usage
Quick Start
bash
python src/combined_scorer.py
Expected Output
text
======================================================================
Service Account Governor - Complete Risk Analysis
======================================================================

📋 Step 1: Discovering service accounts...
📊 Found 2 total IAM roles
  ✓ AWSServiceRoleForSupport → support.amazonaws.com
  ✓ AWSServiceRoleForTrustedAdvisor → trustedadvisor.amazonaws.com

📊 Step 2: Scoring service accounts...

======================================================================
📈 RISK ANALYSIS SUMMARY
======================================================================

🔴 TOP RISKIEST SERVICE ACCOUNTS:

  1. AWSServiceRoleForTrustedAdvisor
     Final Score: 35.5/100 (MEDIUM)
     Privilege: 1/100 | Activity: 100/100
     Recommendation: Review immediately - may be unnecessary

💾 Results exported to risk_analysis_results.csv
Module-by-Module Execution
bash
# Just discovery
python -c "from discovery.find_service_roles import ServiceRoleDiscovery; d = ServiceRoleDiscovery(); print(d.discover_all_service_accounts())"

# Just privilege scoring
python -c "from risk_scoring.privilege_score import PrivilegeScorer; p = PrivilegeScorer(); print(p.calculate_privilege_score('AWSServiceRoleForSupport'))"

# Just activity scoring
python -c "from risk_scoring.activity_score import ActivityScorer; a = ActivityScorer(); print(a.calculate_activity_score('AWSServiceRoleForSupport'))"
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
├── tests/                       # Unit tests
├── outputs/                     # Generated reports
└── docs/                        # Documentation
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
Phase 5: Remediation Automation	📅 Planned	Jira/ServiceNow integration
Phase 6: ML Safe-to-Delete Model	📅 Planned	Predictive deletion safety
Phase 7: Attack Path Integration	📅 Planned	Toxic combination detection
Research Publications
This code supports the following research papers (in progress):

"From Least Privilege to Least Used: A Machine Learning Framework for Cloud IAM Entitlement Risk Scoring" (Q3 2026)

"Service Account Abandonment: Measuring the Machine Identity Attack Surface in Enterprise AWS" (Q4 2026)

License
MIT License - See LICENSE file for details.

Disclaimer
This software is for research and educational purposes only.

Run in a personal AWS sandbox, never in production

The author is not responsible for any unintended modifications

This tool performs read-only operations by design

Always review recommendations before taking remediation action

Author
Nathaniel Dadson

Independent Security Researcher

Focus: AI for Cloud Security, CIEM, Cloud Detection & Response

GitHub: github.com/natedadson

This research is conducted independently and does not represent the views of any employer.

Last Updated
June 2026
