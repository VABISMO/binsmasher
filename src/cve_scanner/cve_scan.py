#!/usr/bin/env python3
"""
cve_scan.py — BinSmasher CVE Auditor CLI entry point.

Usage:
  python3 cve_scan.py [paths…] [options]

  -o / --output-dir    Output directory (default: ~/binscan_reports)
  --threshold          Minimum risk score to include binary (default: 50)
  -v / --verbose       Debug logging
  --single BINARY      Audit a single binary
  --no-taint           Skip taint analysis
  --confidence         Minimum confidence filter: CONFIRMED|PROBABLE|UNCONFIRMED
  --no-html            Skip HTML report generation
"""

import argparse
import os
import re
import sys

from cve_scanner.auditor import CVEAuditor, rprint


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="binscan",
        description="BinSmasher CVE Auditor v3 — Static binary vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  binscan /usr/bin
  binscan --single /tmp/vuln_test -v
  binscan /usr/bin /sbin --threshold 100 --confidence CONFIRMED
  binscan --single ./target --no-taint -o ~/my_reports
""",
    )
    parser.add_argument(
        "paths", nargs="*", default=["/usr/bin", "/usr/sbin", "/lib/modules"],
        help="Directories or files to scan (default: /usr/bin /usr/sbin /lib/modules)",
    )
    parser.add_argument(
        "-o", "--output-dir", default=os.path.expanduser("~/binscan_reports"),
        help="Output directory for reports (default: ~/binscan_reports)",
    )
    parser.add_argument(
        "--threshold", type=int, default=50,
        help="Minimum risk score to include a binary in the report (default: 50)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--single", metavar="BINARY",
        help="Audit a single binary file",
    )
    parser.add_argument(
        "--no-taint", action="store_true",
        help="Disable taint / data-flow analysis",
    )
    parser.add_argument(
        "--confidence",
        choices=["CONFIRMED", "PROBABLE", "UNCONFIRMED"],
        default="PROBABLE",
        help="Minimum confidence level to include in report (default: PROBABLE)",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation",
    )

    args = parser.parse_args()

    # Determine scan paths
    if args.single:
        if not os.path.isfile(args.single):
            print(f"[ERROR] File not found: {args.single}", file=sys.stderr)
            sys.exit(1)
        paths = [args.single]
    else:
        paths = args.paths

    # Create auditor
    auditor = CVEAuditor(
        search_paths=paths,
        output_dir=args.output_dir,
        threshold_score=args.threshold,
        verbose=args.verbose,
        taint=not args.no_taint,
        min_confidence=args.confidence,
    )

    rprint("[bold cyan]▶ BinSmasher CVE Auditor v3[/]")
    rprint(f"[dim]Scanning: {paths}[/]")
    rprint(f"[dim]Output:   {args.output_dir}[/]")
    rprint(f"[dim]Taint:    {not args.no_taint}  |  Min confidence: {args.confidence}[/]")
    rprint("")

    reports = auditor.scan()

    if not reports:
        rprint("[yellow]No findings above threshold.[/]")
        sys.exit(0)

    rprint(f"\n[bold green]✔ Audit complete — {len(reports)} binary/ies with findings[/]\n")

    # ── Exports ──────────────────────────────────────────────────────────
    json_all = auditor.export_json_all(reports)
    json_ch  = auditor.export_json_confirmed_high(reports)
    json_ph  = auditor.export_json_probable_high(reports)
    md_mitre = auditor.export_mitre_templates(reports)

    if not args.no_html:
        html_path = auditor.export_html(reports)

    rprint("\n[bold]Output files:[/]")
    rprint(f"  [green]JSON (all)[/]              → {json_all}")
    rprint(f"  [green]JSON (confirmed+high)[/]   → {json_ch}")
    rprint(f"  [green]JSON (probable+high)[/]    → {json_ph}")
    rprint(f"  [green]MITRE CVE templates[/]     → {md_mitre}")
    if not args.no_html:
        rprint(f"  [green]HTML report[/]             → {html_path}")


if __name__ == "__main__":
    main()