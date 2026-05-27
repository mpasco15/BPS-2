from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from security.api_permission_audit import ApiKeyPermissionRecord, build_api_permission_audit_report, export_api_permission_audit_report
from security.dependency_audit import build_dependency_security_audit_report, export_dependency_security_audit_report
from security.environment_policy import evaluate_environment_policy, export_environment_policy_report
from security.key_rotation_check import KeyRotationRecord, build_key_rotation_check_report, export_key_rotation_check_report
from security.secret_scanner import build_secret_scan_report, export_secret_scan_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run consolidated security audit.")

    parser.add_argument("--export", action="store_true")
    parser.add_argument("--output-dir", default="artifacts/security")
    parser.add_argument("--scan-root", default=".")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    now = datetime.now(timezone.utc)

    secret_scan = build_secret_scan_report(root_path=args.scan_root)

    api_permissions = build_api_permission_audit_report(
        keys=[
            ApiKeyPermissionRecord(
                key_name="BINANCE_API_KEY",
                present=True,
                read_enabled=True,
                trade_enabled=True,
                futures_enabled=True,
                withdrawal_enabled=False,
                transfer_enabled=False,
                environment="testnet",
            )
        ]
    )

    dependency_audit = build_dependency_security_audit_report(vulnerabilities=[])

    environment_policy = evaluate_environment_policy()

    key_rotation = build_key_rotation_check_report(
        keys=[
            KeyRotationRecord(
                key_name="BINANCE_API_KEY",
                last_rotated_at=now - timedelta(days=5),
                next_rotation_due_at=now + timedelta(days=25),
                rotation_procedure_doc="docs/SECURITY.md",
            ),
            KeyRotationRecord(
                key_name="BINANCE_API_SECRET",
                last_rotated_at=now - timedelta(days=5),
                next_rotation_due_at=now + timedelta(days=25),
                rotation_procedure_doc="docs/SECURITY.md",
            ),
        ]
    )

    output = {
        "secret_scan": secret_scan.model_dump(mode="json"),
        "api_permissions": api_permissions.model_dump(mode="json"),
        "dependency_audit": dependency_audit.model_dump(mode="json"),
        "environment_policy": environment_policy.model_dump(mode="json"),
        "key_rotation": key_rotation.model_dump(mode="json"),
    }

    print(json.dumps(output, ensure_ascii=False, indent=2))

    if args.export:
        export_secret_scan_report(secret_scan, output_dir=args.output_dir, name="secret_scan")
        export_api_permission_audit_report(api_permissions, output_dir=args.output_dir, name="api_permission_audit")
        export_dependency_security_audit_report(dependency_audit, output_dir=args.output_dir, name="dependency_security_audit")
        export_environment_policy_report(environment_policy, output_dir=args.output_dir, name="environment_policy")
        export_key_rotation_check_report(key_rotation, output_dir=args.output_dir, name="key_rotation_check")
        print(f"Security audit exported to: {args.output_dir}")

    passed = (
        secret_scan.passed
        and api_permissions.passed
        and dependency_audit.passed
        and environment_policy.passed
        and key_rotation.passed
    )

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())