import os
import json
import boto3
from github import Github
from dotenv import load_dotenv
from scanner.secrets_scanner import scan_repo_for_secrets
from scanner.misconfig_scanner import scan_repo_for_misconfigs
from scanner.policy_scanner import scan_repo_for_policy_violations

# Load .env for local testing
load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME", "sunnyoncloud9")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def format_report(username, results):
    """Format scan results into a readable report."""
    total_secrets = sum(len(r["secrets"]) for r in results)
    total_misconfigs = sum(len(r["misconfigs"]) for r in results)
    total_policies = sum(len(r["policy_violations"]) for r in results)
    total_issues = total_secrets + total_misconfigs + total_policies

    report = []
    report.append("=" * 60)
    report.append("  GITHUB SECURITY SCANNER — SCAN REPORT")
    report.append("=" * 60)
    report.append(f"  Account   : {username}")
    report.append(f"  Repos Scanned : {len(results)}")
    report.append(f"  Total Issues  : {total_issues}")
    report.append(f"  - Exposed Secrets   : {total_secrets}")
    report.append(f"  - Misconfigurations : {total_misconfigs}")
    report.append(f"  - Policy Violations : {total_policies}")
    report.append("=" * 60)

    for repo_result in results:
        repo_name = repo_result["repo"]
        has_issues = (
            repo_result["secrets"] or
            repo_result["misconfigs"] or
            repo_result["policy_violations"]
        )

        if not has_issues:
            continue

        report.append(f"\n📁 REPO: {repo_name}")
        report.append("-" * 40)

        if repo_result["secrets"]:
            report.append("  🔑 EXPOSED SECRETS:")
            for f in repo_result["secrets"]:
                report.append(f"    [{f['type']}] in {f['file']} (line {f['line']})")
                report.append(f"    Snippet: {f['snippet']}")

        if repo_result["misconfigs"]:
            report.append("  ⚙️  MISCONFIGURATIONS:")
            for f in repo_result["misconfigs"]:
                report.append(f"    [{f['severity']}] {f['type']}")
                report.append(f"    {f['detail']}")

        if repo_result["policy_violations"]:
            report.append("  📋 POLICY VIOLATIONS:")
            for f in repo_result["policy_violations"]:
                report.append(f"    [{f['severity']}] {f['type']}")
                report.append(f"    {f['detail']}")

    report.append("\n" + "=" * 60)
    report.append("  Scan complete. Review findings above.")
    report.append("=" * 60)

    return "\n".join(report)


def send_sns_alert(report, total_issues):
    """Send scan report to AWS SNS topic."""
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not set — skipping SNS alert")
        return

    try:
        sns = boto3.client("sns", region_name=AWS_REGION)
        subject = f"[GitHub Security Scanner] {total_issues} Issue(s) Found in {GITHUB_USERNAME}'s Repos"

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject limit
            Message=report
        )
        print("SNS alert sent successfully!")

    except Exception as e:
        print(f"Failed to send SNS alert: {e}")


def lambda_handler(event, context):
    """Main Lambda handler — entry point for AWS Lambda."""
    print(f"Starting GitHub Security Scanner for user: {GITHUB_USERNAME}")

    if not GITHUB_TOKEN:
        raise ValueError("GITHUB_TOKEN environment variable not set")

    # Initialize GitHub client
    from github import Auth
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    user = g.get_user(GITHUB_USERNAME)
    repos = user.get_repos()

    results = []

    for repo in repos:
        print(f"Scanning repo: {repo.name}")

        repo_result = {
            "repo": repo.name,
            "secrets": [],
            "misconfigs": [],
            "policy_violations": []
        }

        # Run all 3 scanners
        repo_result["secrets"] = scan_repo_for_secrets(repo)
        repo_result["misconfigs"] = scan_repo_for_misconfigs(repo)
        repo_result["policy_violations"] = scan_repo_for_policy_violations(repo)

        results.append(repo_result)
        print(f"  → Secrets: {len(repo_result['secrets'])} | Misconfigs: {len(repo_result['misconfigs'])} | Policy: {len(repo_result['policy_violations'])}")

    # Generate report
    report = format_report(GITHUB_USERNAME, results)
    print("\n" + report)

    # Calculate totals
    total_issues = sum(
        len(r["secrets"]) + len(r["misconfigs"]) + len(r["policy_violations"])
        for r in results
    )

    # Send SNS alert if issues found
    if total_issues > 0:
        send_sns_alert(report, total_issues)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Scan complete",
            "username": GITHUB_USERNAME,
            "repos_scanned": len(results),
            "total_issues": total_issues
        })
    }


# For local testing
if __name__ == "__main__":
    lambda_handler({}, {})
