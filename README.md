# nova-cloudguard

# ☁️ Nova-CloudGuard: Multi-Cloud IAM & Threat Surface Auditor

A lightweight Cloud Security Posture Management (CSPM) and Identity Governance scanner designed to audit AWS and multi-cloud environments for over-privileged IAM roles, public S3 buckets, SSRF-vulnerable IMDSv1 endpoints, and stale access keys.

---

## ✨ Features
- **Least-Privilege Role Auditing**: Detects broad administrative wildcard permissions (`Action: *`).
- **Storage Leak Protection**: Flags unauthenticated public access permissions on cloud object storage.
- **SSRF & Metadata Hardening**: Audits EC2 instances to verify mandatory IMDSv2 token enforcement.
- **Credential Lifecycle Management**: Identifies IAM access keys that have not been rotated within the 90-day compliance window.
- **Zero Third-Party Dependencies**: Pure Python standard library implementation (`json`, `datetime`, `os`).

---

## 🚀 Quick Start
```bash
python3 nova_cloudguard.py
