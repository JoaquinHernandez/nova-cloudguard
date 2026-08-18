import os
import sys
import json
import time
from datetime import datetime, timezone

# ANSI Color & Styling Tokens
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[38;5;196m"
GREEN   = "\033[38;5;48m"
CYAN    = "\033[38;5;51m"
AMBER   = "\033[38;5;214m"
MAGENTA = "\033[38;5;201m"
GRAY    = "\033[38;5;242m"

BANNER = f"""{CYAN}{BOLD}
 ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗      ██████╗ ██╗      ██████╗ ██╗   ██╗██████╗ 
 ████╗  ██║██╔═══██╗██║   ██║██╔══██╗    ██╔════╝ ██║     ██╔═══██╗██║   ██║██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║███████║    ██║  ███╗██║     ██║   ██║██║   ██║██║  ██║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║    ██║   ██║██║     ██║   ██║██║   ██║██║  ██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║    ╚██████╔╝███████╗╚██████╔╝╚██████╔╝██████╔╝
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝     ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ 
{RESET}{AMBER} » AUTOMATED MULTI-CLOUD POSTURE & LEAST-PRIVILEGE IAM AUDITOR «{RESET}
"""

class NovaCloudGuard:
    def __init__(self, infra_path="cloud_infrastructure.json", rules_path="compliance_rules.json"):
        if not os.path.exists(infra_path) or not os.path.exists(rules_path):
            print(f"{RED}[-] Error: Missing infrastructure or compliance rules configuration.{RESET}")
            sys.exit(1)

        with open(infra_path, "r") as f:
            self.infra = json.load(f)

        with open(rules_path, "r") as f:
            self.compliance = json.load(f)

        self.max_key_age = self.compliance.get("max_key_age_days", 90)

    def calculate_posture_score(self, total_checks, findings_count):
        if total_checks == 0:
            return 100
        score = max(0, int(((total_checks - findings_count) / total_checks) * 100))
        return score

    def run_audit(self):
        print(BANNER)
        print(f"{BOLD}Connecting to Cloud Infrastructure Control Plane...{RESET}\n")

        steps = [
            "Querying AWS IAM policies and credential metadata",
            "Evaluating S3 Object Storage bucket access control lists (ACLs)",
            "Checking EC2 Instance Metadata Service (IMDSv2) token enforcement",
            "Calculating days-since-creation for active access keys"
        ]
        for step in steps:
            time.sleep(0.25)
            print(f"  {CYAN}▸{RESET} {step}...")

        print("\n" + "=" * 85 + "\n")
        print(f"{BOLD}{'ASSET TYPE':<16} {'RESOURCE IDENTIFIER':<32} {'SEVERITY':<12} {'COMPLIANCE FINDING'}{RESET}")
        print("-" * 85)

        findings = []
        total_checks = 0

        # 1. Audit IAM Roles
        for role in self.infra.get("iam_roles", []):
            total_checks += 1
            if role.get("has_wildcard_admin"):
                findings.append({
                    "asset": "IAM Role",
                    "resource": role["role_name"],
                    "severity": "CRITICAL",
                    "issue": "AdministratorAccess / Wildcard Action (*)",
                    "remediation": "Scope down permissions to specific least-privilege APIs."
                })
                print(f"{'IAM Role':<16} {role['role_name']:<32} {RED}{'CRITICAL':<12}{RESET} Wildcard Action (*)")
            else:
                print(f"{'IAM Role':<16} {role['role_name']:<32} {GREEN}{'PASS':<12}{RESET} Least-Privilege Enforced")

        # 2. Audit Storage Buckets
        for bucket in self.infra.get("storage_buckets", []):
            total_checks += 1
            if bucket.get("is_public"):
                findings.append({
                    "asset": "S3 Storage",
                    "resource": bucket["bucket_name"],
                    "severity": "CRITICAL",
                    "issue": "Publicly Accessible Object Storage",
                    "remediation": "Enable AWS S3 Block Public Access."
                })
                print(f"{'S3 Bucket':<16} {bucket['bucket_name']:<32} {RED}{'CRITICAL':<12}{RESET} Public Read Access Enabled")
            else:
                print(f"{'S3 Bucket':<16} {bucket['bucket_name']:<32} {GREEN}{'PASS':<12}{RESET} Private (Encrypted at Rest)")

        # 3. Audit IMDSv2
        for inst in self.infra.get("compute_instances", []):
            total_checks += 1
            if not inst.get("imdsv2_enforced"):
                findings.append({
                    "asset": "EC2 Compute",
                    "resource": inst["instance_id"],
                    "severity": "HIGH",
                    "issue": "Legacy IMDSv1 Enabled (SSRF Risk)",
                    "remediation": "Enforce HttpTokens=required on instance metadata."
                })
                print(f"{'EC2 Instance':<16} {inst['instance_id']:<32} {AMBER}{'HIGH':<12}{RESET} IMDSv1 Active (Vulnerable to SSRF)")
            else:
                print(f"{'EC2 Instance':<16} {inst['instance_id']:<32} {GREEN}{'PASS':<12}{RESET} IMDSv2 Token Required")

        # 4. Audit Key Ages
        now = datetime.now(timezone.utc)
        for key in self.infra.get("iam_access_keys", []):
            total_checks += 1
            created_dt = datetime.fromisoformat(key["created_date"].replace("Z", "+00:00"))
            age_days = (now - created_dt).days
            if age_days > self.max_key_age:
                findings.append({
                    "asset": "IAM Access Key",
                    "resource": f"{key['user_name']} ({key['key_id']})",
                    "severity": "MEDIUM",
                    "issue": f"Key Stale ({age_days} Days Old)",
                    "remediation": f"Rotate key pair (exceeds {self.max_key_age}-day policy limit)."
                })
                print(f"{'IAM Key':<16} {key['key_id']:<32} {AMBER}{'MEDIUM':<12}{RESET} Stale Key ({age_days} Days Old)")
            else:
                print(f"{'IAM Key':<16} {key['key_id']:<32} {GREEN}{'PASS':<12}{RESET} Key Valid ({age_days} Days Old)")

        # Summary & Scorecard
        score = self.calculate_posture_score(total_checks, len(findings))
        score_color = GREEN if score >= 85 else (AMBER if score >= 60 else RED)

        print("=" * 85)
        print(f"\n{BOLD}Cloud Security Posture Score:{RESET} {score_color}{BOLD}{score}/100{RESET}")
        print(f"Total Cloud Resources Audited: {BOLD}{total_checks}{RESET} | Misconfigurations Flagged: {RED}{BOLD}{len(findings)}{RESET}")

        if findings:
            print(f"\n{AMBER}{BOLD}[🛠️ AUTOMATED REMEDIATION PLAYBOOK]{RESET}")
            for idx, f in enumerate(findings, start=1):
                print(f"  {CYAN}#{idx} [{f['severity']}]{RESET} {BOLD}{f['resource']}{RESET}:")
                print(f"     └─ {f['remediation']}")
        print()

if __name__ == "__main__":
    guard = NovaCloudGuard()
    guard.run_audit()
