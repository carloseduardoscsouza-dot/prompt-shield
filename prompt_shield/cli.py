"""
CLI interface for prompt-shield.
"""

import sys
import json
import argparse
from pathlib import Path
from . import __version__
from .scanner import scan_prompt
from .rules import RiskLevel


def main():
    parser = argparse.ArgumentParser(
        prog="prompt-shield",
        description="Lightweight AI Security & LLM Prompt Linter. Detects prompt injections, secret leaks, and PII.",
    )
    parser.add_argument("prompt", nargs="?", help="Prompt text to scan")
    parser.add_argument("-f", "--file", help="Path to text/markdown file to scan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--mask", action="store_true", help="Print redacted/sanitized prompt")
    parser.add_argument("--strict", action="store_true", help="Fail with exit code 1 if risk is detected")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    content = ""
    if args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            print(f"Error: File '{fpath}' not found.", file=sys.stderr)
            sys.exit(1)
        content = fpath.read_text(encoding="utf-8", errors="replace")
    elif args.prompt:
        content = args.prompt
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    else:
        parser.print_help()
        sys.exit(0)

    result = scan_prompt(content)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"\n[prompt-shield v{__version__}]")
        print(f"Status:      {'PASS' if result.is_safe else 'ALERT'}")
        print(f"Risk Level:  {result.risk_level.value}")
        print(f"Risk Score:  {result.risk_score}/100")
        print(f"Est. Tokens: {result.token_estimate}")
        print(f"Findings:    {len(result.findings)}")

        if result.findings:
            print("\nFindings Detail:")
            for i, f in enumerate(result.findings, 1):
                print(f"  [{i}] [{f.risk.value}] {f.category}: {f.description}")
                preview = f.matched_text.replace('\n', ' ')
                print(f"      Matched: \"{preview[:50]}\"")

        if args.mask:
            print("\nSanitized Prompt:")
            print(result.sanitized_prompt)

    if args.strict and not result.is_safe:
        sys.exit(1)


if __name__ == "__main__":
    main()
