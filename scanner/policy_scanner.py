from github import GithubException


def check_readme(repo):
    """Check if repo has a README file."""
    findings = []

    try:
        readme_files = ["README.md", "README.rst", "README.txt", "README"]
        has_readme = False

        for rf in readme_files:
            try:
                repo.get_contents(rf)
                has_readme = True
                break
            except GithubException:
                continue

        if not has_readme:
            findings.append({
                "type": "Missing README",
                "severity": "LOW",
                "detail": f"Repo '{repo.name}' has no README — undocumented repositories are a security risk"
            })

    except GithubException:
        pass

    return findings


def check_license(repo):
    """Check if repo has a license file."""
    findings = []

    try:
        if repo.license is None:
            findings.append({
                "type": "Missing License",
                "severity": "LOW",
                "detail": f"Repo '{repo.name}' has no license — unclear usage rights can create legal and security risks"
            })
    except GithubException:
        pass

    return findings


def check_open_issues_age(repo):
    """Check if repo has very old unresolved issues (potential security neglect)."""
    findings = []

    try:
        from datetime import datetime, timezone

        open_issues = repo.get_issues(state="open")
        old_issues = []

        for issue in open_issues:
            age_days = (datetime.now(timezone.utc) - issue.created_at).days
            if age_days > 180:  # 6 months old
                old_issues.append(issue)
            if len(old_issues) >= 5:  # Cap at 5 to avoid rate limits
                break

        if len(old_issues) >= 3:
            findings.append({
                "type": "Stale Issues Detected",
                "severity": "LOW",
                "detail": f"Repo '{repo.name}' has {len(old_issues)}+ issues older than 180 days — may indicate maintenance neglect"
            })

    except GithubException:
        pass

    return findings


def check_dependabot(repo):
    """Check if Dependabot alerts are enabled."""
    findings = []

    try:
        # Check for dependabot config file
        dependabot_paths = [".github/dependabot.yml", ".github/dependabot.yaml"]
        has_dependabot = False

        for path in dependabot_paths:
            try:
                repo.get_contents(path)
                has_dependabot = True
                break
            except GithubException:
                continue

        if not has_dependabot and not repo.private:
            findings.append({
                "type": "No Dependabot Configuration",
                "severity": "MEDIUM",
                "detail": f"Repo '{repo.name}' has no Dependabot config — dependency vulnerabilities may go undetected"
            })

    except GithubException:
        pass

    return findings


def check_gitignore(repo):
    """Check if repo has a .gitignore file."""
    findings = []

    try:
        repo.get_contents(".gitignore")
    except GithubException:
        findings.append({
            "type": "Missing .gitignore",
            "severity": "MEDIUM",
            "detail": f"Repo '{repo.name}' has no .gitignore — sensitive files like .env may be accidentally committed"
        })

    return findings


def scan_repo_for_policy_violations(repo):
    """Run all policy violation checks on a repository."""
    findings = []

    findings.extend(check_readme(repo))
    findings.extend(check_license(repo))
    findings.extend(check_dependabot(repo))
    findings.extend(check_gitignore(repo))
    findings.extend(check_open_issues_age(repo))

    return findings
