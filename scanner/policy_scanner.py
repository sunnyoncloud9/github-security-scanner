def check_readme(repo, headers, session):
    findings = []
    try:
        readme_files = ["README.md", "README.rst", "README.txt", "README"]
        has_readme = False
        for rf in readme_files:
            resp = session.get(
                f"https://api.github.com/repos/{repo['full_name']}/contents/{rf}",
                headers=headers
            )
            if resp.status_code == 200:
                has_readme = True
                break
        if not has_readme:
            findings.append({
                "type": "Missing README",
                "severity": "LOW",
                "detail": f"Repo '{repo['name']}' has no README — undocumented repositories are a security risk"
            })
    except Exception:
        pass
    return findings


def check_license(repo):
    findings = []
    if not repo.get("license"):
        findings.append({
            "type": "Missing License",
            "severity": "LOW",
            "detail": f"Repo '{repo['name']}' has no license — unclear usage rights can create legal and security risks"
        })
    return findings


def check_dependabot(repo, headers, session):
    findings = []
    try:
        dependabot_paths = [".github/dependabot.yml", ".github/dependabot.yaml"]
        has_dependabot = False
        for path in dependabot_paths:
            resp = session.get(
                f"https://api.github.com/repos/{repo['full_name']}/contents/{path}",
                headers=headers
            )
            if resp.status_code == 200:
                has_dependabot = True
                break
        if not has_dependabot:
            findings.append({
                "type": "No Dependabot Configuration",
                "severity": "MEDIUM",
                "detail": f"Repo '{repo['name']}' has no Dependabot config — dependency vulnerabilities may go undetected"
            })
    except Exception:
        pass
    return findings


def check_gitignore(repo, headers, session):
    findings = []
    try:
        resp = session.get(
            f"https://api.github.com/repos/{repo['full_name']}/contents/.gitignore",
            headers=headers
        )
        if resp.status_code != 200:
            findings.append({
                "type": "Missing .gitignore",
                "severity": "MEDIUM",
                "detail": f"Repo '{repo['name']}' has no .gitignore — sensitive files like .env may be accidentally committed"
            })
    except Exception:
        pass
    return findings


def scan_repo_for_policy_violations(repo, headers, session):
    findings = []
    findings.extend(check_readme(repo, headers, session))
    findings.extend(check_license(repo))
    findings.extend(check_dependabot(repo, headers, session))
    findings.extend(check_gitignore(repo, headers, session))
    return findings
