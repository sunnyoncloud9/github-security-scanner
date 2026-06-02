def check_repo_visibility(repo):
    findings = []
    if not repo.get("private", False):
        sensitive_keywords = [
            "internal", "private", "secret", "config",
            "credential", "prod", "production", "infra",
            "infrastructure", "deploy", "deployment"
        ]
        name_lower = repo["name"].lower()
        for keyword in sensitive_keywords:
            if keyword in name_lower:
                findings.append({
                    "type": "Potentially Sensitive Public Repo",
                    "severity": "HIGH",
                    "detail": f"Repo '{repo['name']}' is public but name suggests sensitive content (keyword: '{keyword}')"
                })
                break
    return findings


def check_branch_protection(repo, headers, session):
    findings = []
    try:
        default_branch = repo.get("default_branch", "main")
        resp = session.get(
            f"https://api.github.com/repos/{repo['full_name']}/branches/{default_branch}",
            headers=headers
        )
        if resp.status_code == 200:
            branch_data = resp.json()
            if not branch_data.get("protected", False):
                findings.append({
                    "type": "No Branch Protection",
                    "severity": "MEDIUM",
                    "detail": f"Default branch '{default_branch}' has no protection rules — anyone can force push or delete"
                })
    except Exception:
        pass
    return findings


def check_security_policy(repo, headers, session):
    findings = []
    try:
        security_files = ["SECURITY.md", "security.md", ".github/SECURITY.md"]
        has_security = False
        for sf in security_files:
            resp = session.get(
                f"https://api.github.com/repos/{repo['full_name']}/contents/{sf}",
                headers=headers
            )
            if resp.status_code == 200:
                has_security = True
                break
        if not has_security:
            findings.append({
                "type": "Missing Security Policy",
                "severity": "LOW",
                "detail": f"Repo '{repo['name']}' has no SECURITY.md file — no vulnerability disclosure process defined"
            })
    except Exception:
        pass
    return findings


def check_default_branch_name(repo):
    findings = []
    if repo.get("default_branch") == "master":
        findings.append({
            "type": "Outdated Default Branch Name",
            "severity": "LOW",
            "detail": f"Repo '{repo['name']}' uses 'master' as default branch — consider renaming to 'main'"
        })
    return findings


def scan_repo_for_misconfigs(repo, headers, session):
    findings = []
    findings.extend(check_repo_visibility(repo))
    findings.extend(check_branch_protection(repo, headers, session))
    findings.extend(check_security_policy(repo, headers, session))
    findings.extend(check_default_branch_name(repo))
    return findings
