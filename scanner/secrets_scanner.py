import re
import base64
from github import GithubException

# Regex patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic Password": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",
    "Generic API Key": r"(?i)(api_key|apikey|api-key)\s*=\s*['\"][^'\"]{10,}['\"]",
    "Generic Secret": r"(?i)(secret|token)\s*=\s*['\"][^'\"]{10,}['\"]",
}

# Files to skip
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
    """Scan a single file's content for secret patterns."""
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, line):
                # Mask the actual secret in the finding
                findings.append({
                    "type": secret_type,
                    "file": filename,
                    "line": line_num,
                    "snippet": line.strip()[:80] + "..." if len(line.strip()) > 80 else line.strip()
                })
                break  # One finding per line

    return findings


def scan_repo_for_secrets(repo):
    """Scan all files in a repository for exposed secrets."""
    findings = []

    try:
        contents = repo.get_contents("")
        files_to_scan = []

        # Recursively collect all files
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                try:
                    contents.extend(repo.get_contents(file_content.path))
                except GithubException:
                    continue
            else:
                files_to_scan.append(file_content)

        # Scan each file
        for file in files_to_scan:
            # Skip binary and irrelevant files
            ext = "." + file.name.split(".")[-1] if "." in file.name else ""
            if ext.lower() in SKIP_EXTENSIONS or file.name in SKIP_FILES:
                continue

            # Skip large files (>500KB)
            if file.size > 500000:
                continue

            try:
                if file.encoding == "base64" and file.content:
                    decoded = base64.b64decode(file.content).decode("utf-8", errors="ignore")
                    file_findings = scan_file_for_secrets(decoded, file.path)
                    findings.extend(file_findings)
            except Exception:
                continue

    except GithubException as e:
        print(f"Error scanning repo {repo.name}: {e}")

    return findings
