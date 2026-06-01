from github import GithubException


def check_repo_visibility(repo):
    """Check if repo is public when it might contain sensitive data."""
    findings = []

    if not repo.private:
        # Check for potentially sensitive repo names
        sensitive_keywords = [
            "internal", "private", "secret", "config",
            "credential", "prod", "production", "infra",
            "infrastructure", "deploy", "deployment"
        ]
        name_lower = repo.name.lower()
        for keyword in sensitive_keywords:
            if keyword in name_lower:
                findings.append({
                    "type": "Potentially Sensitive Public Repo",
                    "severity": "HIGH",
                    "detail": f"Repo '{repo.name}' is public but name suggests sensitive content (keyword: '{keyword}')"
                })
                break

    return findings


def check_branch_protection(repo):
    """Check if default branch has protection rules enabled."""
    findings = []

    try:
        default_branch = repo.default_branch
        branch = repo.get_branch(default_branch)

        if not branch.protected:
            findings.append({
                "type": "No Branch Protection",
                "severity": "MEDIUM",
                "detail": f"Default branch '{default_branch}' has no protection rules — anyone can force push or delete"
            })
        else:
            # Check specific protection settings
            protection = branch.get_protection()
            try:
                reviews = protection.required_pull_request_reviews
                if reviews is None:
                    findings.append({
                        "type": "No PR Reviews Required",
                        "severity": "MEDIUM",
                        "detail": f"Branch '{default_branch}' is protected but does not require pull request reviews"
                    })
            except Exception:
                pass

    except GithubException:
        pass  # Repo may be empty or branch not accessible

    return findings


def check_security_policy(repo):
    """Check if repo has a SECURITY.md policy file."""
    findings = []

    try:
        security_files = ["SECURITY.md", "security.md", ".github/SECURITY.md"]
        has_security = False

        for sf in security_files:
            try:
                repo.get_contents(sf)
                has_security = True
                break
            except GithubException:
                continue

        if not has_security:
            findings.append({
                "type": "Missing Security Policy",
                "severity": "LOW",
                "detail": f"Repo '{repo.name}' has no SECURITY.md file — no vulnerability disclosure process defined"
            })

    except GithubException:
        pass

    return findings


def check_default_branch_name(repo):
    """Check if repo still uses 'master' as default branch."""
    findings = []

    if repo.default_branch == "master":
        findings.append({
            "type": "Outdated Default Branch Name",
            "severity": "LOW",
            "detail": f"Repo '{repo.name}' uses 'master' as default branch — consider renaming to 'main'"
        })

    return findings


def scan_repo_for_misconfigs(repo):
    """Run all misconfiguration checks on a repository."""
    findings = []

    findings.extend(check_repo_visibility(repo))
    findings.extend(check_branch_protection(repo))
    findings.extend(check_security_policy(repo))
    findings.extend(check_default_branch_name(repo))

    return findings
