import re
import base64

# Regex patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic Password": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",
    "Generic API Key": r"(?i)(api_key|apikey|api-key)\s*=\s*['\"][^'\"]{10,}['\"]",
    "Generic Secret": r"(?i)(secret|token)\s*=\s*['\"][^'\"]{10,}['\"]",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".bin", ".exe",
    ".lock", ".sum", ".mod"
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    "Pipfile.lock", "requirements.txt"
}


def scan_file_for_secrets(content, filename):
    findings = []
    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, line):
                findings.append({
                    "type": secret_type,
                    "file": filename,
                    "line": line_num,
                    "snippet": line.strip()[:80] + "..." if len(line.strip()) > 80 else line.strip()
                })
                break
    return findings


def scan_repo_for_secrets(repo_full_name, headers, session):
    findings = []
    try:
        repo_resp = session.get(f"https://api.github.com/repos/{repo_full_name}", headers=headers)
        if repo_resp.status_code != 200:
            return findings
        default_branch = repo_resp.json().get("default_branch", "main")

        tree_resp = session.get(
            f"https://api.github.com/repos/{repo_full_name}/git/trees/{default_branch}?recursive=1",
            headers=headers
        )
        if tree_resp.status_code != 200:
            return findings

        tree = tree_resp.json().get("tree", [])

        for item in tree:
            if item["type"] != "blob":
                continue
            path = item["path"]
            filename = path.split("/")[-1]
            ext = "." + filename.split(".")[-1] if "." in filename else ""

            if ext.lower() in SKIP_EXTENSIONS or filename in SKIP_FILES:
                continue
            if item.get("size", 0) > 500000:
                continue

            content_resp = session.get(
                f"https://api.github.com/repos/{repo_full_name}/contents/{path}",
                headers=headers
            )
            if content_resp.status_code != 200:
                continue

            content_data = content_resp.json()
            if content_data.get("encoding") == "base64" and content_data.get("content"):
                try:
                    decoded = base64.b64decode(content_data["content"]).decode("utf-8", errors="ignore")
                    file_findings = scan_file_for_secrets(decoded, path)
                    findings.extend(file_findings)
                except Exception:
                    continue

    except Exception as e:
        print(f"Error scanning secrets for {repo_full_name}: {e}")

    return findings
