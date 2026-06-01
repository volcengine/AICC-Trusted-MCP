#!/usr/bin/env python3
"""Smoke test for the reusable TDX API module.

This script exercises the public interfaces from ``tdx_api.py`` and prints
JSON responses in a readable format.
"""

from __future__ import annotations

import argparse
import json

try:
    from bytedance.tdx_api.tdx_api import (
        DEFAULT_ATTEST_SERVICE_ENDPOINT,
        appraise_quote_from_files,
        attest_tdx_quote,
        fetch_td_eventlog,
        get_raw_tdx_quote,
        get_tee_status,
    )
except ImportError:
    from tdx_api import (  # type: ignore
        DEFAULT_ATTEST_SERVICE_ENDPOINT,
        appraise_quote_from_files,
        attest_tdx_quote,
        fetch_td_eventlog,
        get_raw_tdx_quote,
        get_tee_status,
    )


def _print_section(title: str, payload: dict) -> None:
    print(f"\n== {title} ==")
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _check_result(name: str, payload: dict, strict: bool, failures: list[str]) -> None:
    status = payload.get("status")
    if status == 200:
        print(f"[PASS] {name}")
        return

    message = payload.get("error") or payload.get("message") or "unknown error"
    print(f"[FAIL] {name}: {message}")
    if strict:
        failures.append(name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test the reusable TDX API")
    parser.add_argument(
        "--attest-url",
        default=DEFAULT_ATTEST_SERVICE_ENDPOINT,
        help="Attestation service URL used by attest_tdx_quote",
    )
    parser.add_argument(
        "--skip-attest",
        action="store_true",
        help="Skip the attestation call",
    )
    parser.add_argument(
        "--skip-eventlog",
        action="store_true",
        help="Skip the TD event log call",
    )
    parser.add_argument(
        "--eventlog-file",
        default="tdeventlog.txt",
        help="Optional output file for fetch_td_eventlog",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any call returns a non-200 status",
    )
    parser.add_argument(
        "--quote-file",
        default=None,
        help="Quote binary path for quote appraisal test",
    )
    parser.add_argument(
        "--tenant-policy-file",
        default=None,
        help="Tenant policy file path for quote appraisal test",
    )
    parser.add_argument(
        "--platform-policy-file",
        default=None,
        help="Optional platform policy file path for quote appraisal test",
    )
    parser.add_argument(
        "--pubkey-file",
        default=None,
        help="Optional public key file for policy owner authentication",
    )
    parser.add_argument(
        "--skip-appraisal",
        action="store_true",
        help="Skip quote appraisal call",
    )
    parser.add_argument(
        "--appraisal-only",
        action="store_true",
        help="Run only quote appraisal test and skip other API calls",
    )
    args = parser.parse_args()

    failures: list[str] = []

    if not args.appraisal_only:
        raw_quote = get_raw_tdx_quote()
        _print_section("get_raw_tdx_quote", raw_quote)
        _check_result("get_raw_tdx_quote", raw_quote, args.strict, failures)

        tee_status = get_tee_status()
        _print_section("get_tee_status", tee_status)
        _check_result("get_tee_status", tee_status, args.strict, failures)

        if not args.skip_attest:
            attest_result = attest_tdx_quote(args.attest_url)
            _print_section("attest_tdx_quote", attest_result)
            _check_result("attest_tdx_quote", attest_result, args.strict, failures)

        if not args.skip_eventlog:
            eventlog_result = fetch_td_eventlog(output_file=args.eventlog_file)
            _print_section("fetch_td_eventlog", eventlog_result)
            _check_result("fetch_td_eventlog", eventlog_result, args.strict, failures)

    if not args.skip_appraisal:
        if args.quote_file and args.tenant_policy_file:
            appraisal_result = appraise_quote_from_files(
                quote_file=args.quote_file,
                tenant_policy_file=args.tenant_policy_file,
                platform_policy_file=args.platform_policy_file,
                pubkey_file=args.pubkey_file,
                verbose=True,
            )
            _print_section("appraise_quote_from_files", appraisal_result)
            _check_result("appraise_quote_from_files", appraisal_result, args.strict, failures)
        else:
            print("\n[SKIP] appraise_quote_from_files: provide --quote-file and --tenant-policy-file")

    if failures:
        print(f"\nCompleted with {len(failures)} failure(s): {', '.join(failures)}")
        return 1

    print("\nCompleted successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
