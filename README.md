# GitHub Security Scanner 🔍

> Serverless AWS Lambda scanner that detects exposed secrets, misconfigurations, and policy violations across GitHub repositories — triggers SNS alerts on detection.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange?style=flat-square&logo=amazonaws)
![AWS SNS](https://img.shields.io/badge/AWS-SNS-orange?style=flat-square&logo=amazonaws)
![GitHub API](https://img.shields.io/badge/GitHub-API-black?style=flat-square&logo=github)

---

## 📌 Overview

The **GitHub Security Scanner** is a serverless security tool built on AWS Lambda that automatically scans all repositories under a GitHub account for:

- 🔑 **Exposed Secrets** — API keys, tokens, passwords, private keys
- ⚙️ **Misconfigurations** — missing branch protection, sensitive public repos
- 📋 **Policy Violations** — missing README, .gitignore, Dependabot, license

When issues are detected, an alert is automatically sent via **AWS SNS** (email notification). The scanner runs on a schedule via **AWS EventBridge**.

---

## 🏗️ Architecture

```
GitHub API
    │
    ▼
AWS Lambda (Scanner)
    ├── secrets_scanner.py     → Regex-based secret detection
    ├── misconfig_scanner.py   → Repo configuration checks
    └── policy_scanner.py      → Policy compliance checks
    │
    ▼
AWS SNS → Email Alert
    │
AWS EventBridge → Scheduled trigger (daily)
```

---

## 🔍 What It Detects

### Exposed Secrets
| Secret Type | Pattern |
|-------------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub Token | `ghp_[a-zA-Z0-9]{36}` |
| Slack Token | `xox[baprs]-...` |
| Stripe API Key | `sk_live_...` |
| Google API Key | `AIza...` |
| Private Keys | `-----BEGIN PRIVATE KEY-----` |
| Generic Passwords | `password = "..."` |
| Generic API Keys | `api_key = "..."` |

### Misconfigurations
- Public repos with sensitive names (prod, infra, internal, config)
- Missing branch protection on default branch
- No PR review requirements
- Missing SECURITY.md policy
- Outdated `master` branch naming

### Policy Violations
- Missing README
- Missing LICENSE
- Missing .gitignore
- No Dependabot configuration
- Stale issues (180+ days old)

---

## 🚀 Local Setup

### 1. Clone the repo
```bash
git clone https://github.com/sunnyoncloud9/github-security-scanner.git
cd github-security-scanner
```

### 2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment variables
```bash
cp .env.example .env
```

Edit `.env`:
```
GITHUB_TOKEN=your_github_personal_access_token
GITHUB_USERNAME=your_github_username
SNS_TOPIC_ARN=your_sns_topic_arn
AWS_REGION=us-east-1
```

### 4. Run locally
```bash
python lambda_function.py
```

---

## ☁️ AWS Deployment

### Prerequisites
- AWS CLI configured (`aws configure`)
- IAM role with `AWSLambdaBasicExecutionRole` + `SNS:Publish` permissions

### 1. Create SNS Topic
```bash
aws sns create-topic --name github-security-alerts
aws sns subscribe --topic-arn <TOPIC_ARN> --protocol email --notification-endpoint your@email.com
```

### 2. Package Lambda
```bash
mkdir lambda_package
pip install -r requirements.txt -t lambda_package/
cp -r scanner lambda_package/
cp lambda_function.py lambda_package/
cd lambda_package && zip -r ../github-security-scanner.zip . && cd ..
```

### 3. Deploy Lambda
```bash
aws lambda create-function \
  --function-name github-security-scanner \
  --runtime python3.11 \
  --role arn:aws:iam::<ACCOUNT_ID>:role/<LAMBDA_ROLE> \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://github-security-scanner.zip \
  --timeout 300 \
  --memory-size 256
```

### 4. Set Environment Variables
```bash
aws lambda update-function-configuration \
  --function-name github-security-scanner \
  --environment "Variables={GITHUB_TOKEN=<TOKEN>,GITHUB_USERNAME=sunnyoncloud9,SNS_TOPIC_ARN=<ARN>,AWS_REGION=us-east-1}"
```

### 5. Schedule with EventBridge (daily at 9AM UTC)
```bash
aws events put-rule \
  --name github-scanner-daily \
  --schedule-expression "cron(0 9 * * ? *)"

aws events put-targets \
  --rule github-scanner-daily \
  --targets "Id=1,Arn=<LAMBDA_ARN>"
```

---

## 📊 Sample Output

```
============================================================
  GITHUB SECURITY SCANNER — SCAN REPORT
============================================================
  Account       : sunnyoncloud9
  Repos Scanned : 8
  Total Issues  : 12
  - Exposed Secrets   : 2
  - Misconfigurations : 4
  - Policy Violations : 6
============================================================

📁 REPO: my-project
----------------------------------------
  🔑 EXPOSED SECRETS:
    [AWS Access Key] in config/settings.py (line 14)
    Snippet: AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

  ⚙️  MISCONFIGURATIONS:
    [MEDIUM] No Branch Protection
    Default branch 'main' has no protection rules

  📋 POLICY VIOLATIONS:
    [MEDIUM] No Dependabot Configuration
    Repo has no Dependabot config — dependency vulnerabilities may go undetected
============================================================
```

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.11 | Core scanner logic |
| AWS Lambda | Serverless execution |
| AWS SNS | Email alerting |
| AWS EventBridge | Scheduled trigger |
| GitHub API (PyGithub) | Repository scanning |
| boto3 | AWS SDK |

---

## 📁 Project Structure

```
github-security-scanner/
├── scanner/
│   ├── __init__.py
│   ├── secrets_scanner.py      # Secret detection engine
│   ├── misconfig_scanner.py    # Misconfiguration checks
│   └── policy_scanner.py       # Policy violation checks
├── lambda_function.py          # Lambda handler + report generator
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## 🔐 Security Notes

- GitHub token is stored as an AWS Lambda environment variable — never hardcoded
- `.env` file is gitignored and never committed
- Scanner reads repos but never modifies them (read-only token scopes)

---

## 👤 Author

**Sunny Bhardwaj** — Security Engineer  
[github.com/sunnyoncloud9](https://github.com/sunnyoncloud9) 
[linkedin.com/in/bhardwajsunny](https://linkedin.com/in/bhardwajsunny)

---

*Part of a multi-phase security engineering portfolio*
