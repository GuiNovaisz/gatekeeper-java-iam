"""Credential-pattern audit. Prints paths/counts only, never matching values."""
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
files = [root / name for name in tracked if name]
for folder in ("target/surefire-reports", "target/failsafe-reports", "target/evidence"):
    files.extend(p for p in (root / folder).glob("**/*") if p.is_file())
patterns = {
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----"),
    "jwt": re.compile(rb"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}"),
    "bearer-value": re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9_-]{20,}", re.I),
    "github-token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    "totp-uri-value": re.compile(rb"otpauth://[^\s\"<>]*secret=[A-Z2-7]{16,}"),
}
findings = []
for path in set(files):
    if not path.exists() or path.suffix in (".jar", ".class", ".png"):
        continue
    data = path.read_bytes()
    for kind, pattern in patterns.items():
        if pattern.search(data):
            findings.append((str(path.relative_to(root)), kind))
for path, kind in findings:
    print(f"credential-pattern finding: file={path} kind={kind} value=<redacted>")
print(f"G19_ARTIFACT_SCAN files={len(set(files))} findings={len(findings)}")
sys.exit(bool(findings))
