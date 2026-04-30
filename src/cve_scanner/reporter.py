#!/usr/bin/env python3
"""
reporter.py — HTML, JSON, and MITRE CVE export functions.

Generates interactive HTML reports, JSON data files, and MITRE CVE 5.0
submission templates from audit results.
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .models import VulnPoint, BinaryReport
from .scoring import _cvss_vector


# ── Helpers ────────────────────────────────────────────────────────────────────

def _he(s: str) -> str:
    """HTML escape."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _bar_chart(title: str, items: list) -> str:
    """Generate an HTML bar chart widget."""
    total_max = max((x[1] for x in items), default=1) or 1
    bars = ""
    for label, count, color, _ in items:
        pct = int(count / total_max * 100) if total_max else 0
        bars += f"""
<div class="bar-item">
  <span class="bar-key">{label}</span>
  <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>
  <span class="bar-val">{count}</span>
</div>"""
    return f"""<div class="chart-box">
  <div class="chart-label">{title}</div>
  {bars}
</div>"""


# ── JSON exports ──────────────────────────────────────────────────────────────

def export_json_all(reports: List[BinaryReport], output_dir: Path, ts_func) -> Path:
    """Export all findings as JSON."""
    path = output_dir / f"cve_audit_all_{ts_func()}.json"
    path.write_text(json.dumps([asdict(r) for r in reports], indent=2))
    return path


def export_json_confirmed_high(reports: List[BinaryReport], output_dir: Path, ts_func) -> Path:
    """Export CONFIRMED + High/Critical findings as JSON."""
    out = []
    for r in reports:
        vps = [
            v for v in r.vuln_points
            if v.confidence == "CONFIRMED"
            and v.severity in ("Critical", "High")
        ]
        if vps:
            d = asdict(r)
            d["vuln_points"] = [asdict(v) for v in vps]
            out.append(d)
    path = output_dir / f"cve_audit_confirmed_high_{ts_func()}.json"
    path.write_text(json.dumps(out, indent=2))
    return path


def export_json_probable_high(reports: List[BinaryReport], output_dir: Path, ts_func) -> Path:
    """Export PROBABLE + High/Critical findings as JSON."""
    out = []
    for r in reports:
        vps = [
            v for v in r.vuln_points
            if v.confidence == "PROBABLE"
            and v.severity in ("Critical", "High")
        ]
        if vps:
            d = asdict(r)
            d["vuln_points"] = [asdict(v) for v in vps]
            out.append(d)
    path = output_dir / f"cve_audit_probable_high_{ts_func()}.json"
    path.write_text(json.dumps(out, indent=2))
    return path


# ── MITRE CVE submission templates ────────────────────────────────────────────

def export_mitre_templates(reports: List[BinaryReport], output_dir: Path, ts_func) -> Path:
    """
    Generate MITRE CVE 5.0 JSON submission templates and Markdown summary
    for every CONFIRMED + High/Critical finding.
    """
    entries = []
    ts_now  = datetime.now(timezone.utc).isoformat()

    for r in reports:
        for v in r.vuln_points:
            if v.confidence != "CONFIRMED":
                continue
            if v.severity not in ("Critical", "High"):
                continue

            entry = {
                "dataType":    "CVE_RECORD",
                "dataVersion": "5.0",
                "cveMetadata": {
                    "cveId":          f"CVE-PENDING-{v.vuln_id}",
                    "assignerOrgId":  "YOUR-ORG-UUID",
                    "assignerShortName": "YourOrg",
                    "state":          "PUBLISHED",
                    "dateReserved":   ts_now,
                    "datePublished":  ts_now,
                    "dateUpdated":    ts_now,
                },
                "containers": {
                    "cna": {
                        "providerMetadata": {
                            "orgId":       "YOUR-ORG-UUID",
                            "shortName":   "YourOrg",
                            "dateUpdated": ts_now,
                        },
                        "title": (
                            f"{v.category} in {r.binary_name} via {v.function_name}()"
                        ),
                        "descriptions": [
                            {
                                "lang":  "en",
                                "value": (
                                    f"{v.description}. "
                                    f"Found in binary '{r.binary_name}' "
                                    f"(SHA-256: {r.binary_hash_sha256}) "
                                    f"at address {v.location}. "
                                    f"Binary protections: "
                                    f"NX={r.nx}, PIE={r.pie}, "
                                    f"Canary={r.canary}, RELRO={r.relro}."
                                ),
                            }
                        ],
                        "affected": [
                            {
                                "vendor":    "UNKNOWN — to be identified",
                                "product":   r.binary_name,
                                "versions":  [
                                    {
                                        "version":       "unknown",
                                        "status":        "affected",
                                        "versionType":   "custom",
                                    }
                                ],
                                "defaultStatus": "affected",
                                "platform": f"{r.arch} {r.bits}-bit {r.platform}",
                                "kernelModule": r.is_kernel_module,
                            }
                        ],
                        "problemTypes": [
                            {
                                "descriptions": [
                                    {
                                        "type":        "CWE",
                                        "cweId":       v.cwe,
                                        "lang":        "en",
                                        "description": v.description,
                                    }
                                ]
                            }
                        ],
                        "metrics": [
                            {
                                "format":   "CVSS",
                                "scenarios": [
                                    {"lang": "en", "value": "GENERAL"}
                                ],
                                "cvssV3_1": {
                                    "version":             "3.1",
                                    "baseScore":           v.cvss_base,
                                    "baseSeverity":        v.severity.upper(),
                                    "vectorString":        _cvss_vector(v),
                                    "attackVector":        "NETWORK" if v.category in ("BufferOverflow","CommandInjection","FormatString","NetworkExposed") else "LOCAL",
                                    "attackComplexity":    "LOW",
                                    "privilegesRequired":  "L" if ("SUID" in v.description or v.category == "PrivilegeEscalation") else "N",
                                    "userInteraction":     "NONE",
                                    "scope":               "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact":     "HIGH",
                                    "availabilityImpact":  "HIGH",
                                },
                            }
                        ],
                        "references": [
                            {
                                "url":  "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING",
                                "name": "MITRE CVE Pending",
                                "tags": ["vendor-advisory"],
                            },
                            {
                                "url":  f"https://cwe.mitre.org/data/definitions/{v.cwe.replace('CWE-','')}.html",
                                "name": f"{v.cwe} Reference",
                                "tags": ["technical-description"],
                            },
                        ],
                        "timeline": [
                            {"time": ts_now, "lang": "en", "value": "Vulnerability discovered via automated static analysis"},
                            {"time": ts_now, "lang": "en", "value": "CVE reserved / pending assignment"},
                        ],
                        "solutions": [
                            {"lang": "en", "value": v.mitigation}
                        ],
                        "workarounds": [
                            {"lang": "en", "value": "Apply compiler hardening flags and restrict binary permissions."}
                        ],
                        "credits": [
                            {
                                "lang":  "en",
                                "value": "Discovered using BinSmasher CVE Auditor (static analysis)",
                                "type":  "finder",
                            }
                        ],
                        "source": {
                            "discovery":      "INTERNAL",
                            "tool":           "BinSmasher CVE Auditor v3",
                            "binaryHash":     r.binary_hash_sha256,
                            "auditId":        v.vuln_id,
                            "taintConfidence": v.confidence,
                            "callSites":      v.call_sites,
                            "evidence":       v.evidence,
                        },
                    },
                },
            }
            entries.append(entry)

    # Markdown summary for human reading
    lines = [
        "# MITRE CVE Submission Report — BinSmasher CVE Auditor v3\n",
        f"Generated: {ts_now}\n",
        f"Scope: CONFIRMED + High/Critical findings only\n",
        "---\n",
    ]
    for e in entries:
        cna = e["containers"]["cna"]
        m   = cna["metrics"][0]["cvssV3_1"]
        lines += [
            f"\n## {e['cveMetadata']['cveId']}  —  {cna['title']}\n",
            f"\n### Vulnerability Description\n",
            f"{cna['descriptions'][0]['value']}\n",
            f"\n### CVSS 3.1\n",
            f"- Base Score: **{m['baseScore']}** ({m['baseSeverity']})\n",
            f"- Vector:     `{m['vectorString']}`\n",
            f"- Attack Vector: {m['attackVector']}\n",
            f"\n### Weakness Classification\n",
            f"- {cna['problemTypes'][0]['descriptions'][0]['cweId']}: "
            f"{cna['problemTypes'][0]['descriptions'][0]['description']}\n",
            f"\n### Affected Product\n",
            f"- Binary: `{cna['affected'][0]['product']}`\n",
            f"\n### Evidence\n",
        ]
        for ev in cna["source"].get("evidence", []):
            lines.append(f"- `{ev}`\n")
        lines += [
            f"\n### Solution\n",
            f"{cna['solutions'][0]['value']}\n",
            f"\n### References\n",
        ]
        for ref in cna["references"]:
            lines.append(f"- [{ref['name']}]({ref['url']})\n")
        lines.append("\n---\n")

    # Write JSON templates
    json_path = output_dir / f"cve_mitre_json_{ts_func()}.json"
    json_path.write_text(json.dumps(entries, indent=2))

    # Write markdown
    md_path = output_dir / f"cve_mitre_{ts_func()}.md"
    md_path.write_text("".join(lines))

    return md_path


# ── HTML report ────────────────────────────────────────────────────────────────

def export_html(reports: List[BinaryReport], output_dir: Path, ts_func) -> Path:
    """Generate an interactive HTML audit report."""
    path = output_dir / f"cve_audit_{ts_func()}.html"
    path.write_text(_render_html(reports))
    return path


def _render_html(reports: list) -> str:  # noqa: C901
    """Build the full HTML report string."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Collect all vuln points for global stats
    all_vps = [vp for r in reports for vp in r.vuln_points]
    total_confirmed = sum(1 for v in all_vps if v.confidence == "CONFIRMED")
    total_probable  = sum(1 for v in all_vps if v.confidence == "PROBABLE")
    total_critical  = sum(1 for v in all_vps if v.severity == "Critical")
    total_high      = sum(1 for v in all_vps if v.severity == "High")

    sev_color = {
        "Critical": "#ff2d55",
        "High":     "#ff9f0a",
        "Medium":   "#ffd60a",
        "Low":      "#30d158",
    }
    conf_color = {
        "CONFIRMED":   "#30d158",
        "PROBABLE":    "#ffd60a",
        "UNCONFIRMED": "#636366",
    }

    # ── per-report rows ───────────────────────────────────────────────────
    report_rows = []
    for r in reports:
        for v in r.vuln_points:
            ev_html = "".join(
                f'<div class="ev-item">{_he(e)}</div>'
                for e in v.evidence
            )
            sites_html = ", ".join(v.call_sites) if v.call_sites else v.location

            report_rows.append(f"""
<tr
  data-binary="{_he(r.binary_name)}"
  data-confidence="{v.confidence}"
  data-severity="{v.severity}"
  data-category="{v.category}"
  data-cwe="{v.cwe}"
  data-function="{v.function_name}"
>
  <td><span class="badge-id">{_he(v.vuln_id)}</span></td>
  <td>
    <span class="badge-conf" style="--c:{conf_color.get(v.confidence,'#888')}">{v.confidence}</span>
  </td>
  <td>
    <strong>{_he(r.binary_name)}</strong>
    <div class="meta">
      {_he(r.arch)} · {r.bits}-bit · {_he(r.platform)}<br>
      MD5: <code>{r.binary_hash_md5}</code>
    </div>
  </td>
  <td>
    <span class="cat-tag">{_he(v.category)}</span>
  </td>
  <td><a class="cwe-link" href="https://cwe.mitre.org/data/definitions/{v.cwe.replace('CWE-','')}.html" target="_blank">{v.cwe}</a></td>
  <td><code class="fn-name">{_he(v.function_name)}</code></td>
  <td class="addr">{_he(sites_html)}</td>
  <td>
    <span class="cvss-badge" style="--c:{sev_color.get(v.severity,'#888')}">{v.cvss_base}</span>
  </td>
  <td>
    <span class="sev-badge" style="--c:{sev_color.get(v.severity,'#888')}">{v.severity}</span>
  </td>
  <td>
    <div class="prot-row">
      <span class="p {'p-ok' if r.nx else 'p-no'}">NX</span>
      <span class="p {'p-ok' if r.pie else 'p-no'}">PIE</span>
      <span class="p {'p-ok' if r.canary else 'p-no'}">SSP</span>
      <span class="p {'p-ok' if r.relro=='Full' else 'p-partial' if r.relro=='Partial' else 'p-no'}">RELRO</span>
      <span class="p {'p-no' if r.stack_exec else 'p-ok'}">NX-STK</span>
      {"".join('<span class="p p-ok">CAP:' + _he(c) + '</span>' for c in r.linux_caps[:3])}
    </div>
  </td>
  <td>
    <button class="ev-btn" onclick="toggleEvidence(this)">▼ Evidence</button>
    <div class="ev-panel" style="display:none">{ev_html}<div class="mitigation"><strong>Fix:</strong> {_he(v.mitigation)}</div></div>
  </td>
</tr>
""")

    # ── binary summary cards ──────────────────────────────────────────────
    cards_html = ""
    for r in reports:
        confirmed_cnt = sum(1 for v in r.vuln_points if v.confidence == "CONFIRMED")
        high_crit_cnt = sum(1 for v in r.vuln_points if v.severity in ("Critical","High"))
        prot_tags = "".join([
            f'<span class="ptag {"ptok" if r.nx else "ptno"}">NX</span>',
            f'<span class="ptag {"ptok" if r.pie else "ptno"}">PIE</span>',
            f'<span class="ptag {"ptok" if r.canary else "ptno"}">Canary</span>',
            f'<span class="ptag {"ptok" if r.relro=="Full" else "ptpart" if r.relro=="Partial" else "ptno"}">{r.relro} RELRO</span>',
            f'<span class="ptag {"ptok" if r.fortify else "ptno"}">FORTIFY{" L"+str(r.fortify_level) if r.fortify_level else ""}</span>',
            f'<span class="ptag {"ptno" if r.stack_exec else "ptok"}">Exec-Stack</span>',
        ])
        extra_info = ""
        if r.is_kernel_module:
            extra_info += '<div style="color:#bf5af2;font-size:.78rem;margin:2px 0">⬡ Kernel Module</div>'
        if r.has_linux_caps:
            extra_info += f'<div style="color:#ff9f0a;font-size:.78rem;margin:2px 0">⚠ Caps: {_he(", ".join(r.linux_caps[:3]))}</div>'
        if r.rpath_issues:
            extra_info += f'<div style="color:#ff9f0a;font-size:.78rem;margin:2px 0">⚠ RPATH: {_he("; ".join(r.rpath_issues[:2]))}</div>'
        if r.version_cves:
            extra_info += f'<div style="color:#ff2d55;font-size:.78rem;margin:2px 0">⚠ {len(r.version_cves)} known system CVE(s)</div>'
        cards_html += f"""
<div class="card" data-score="{r.risk_score}">
  <div class="card-top">
    <span class="card-name">{_he(r.binary_name)}</span>
    <span class="card-score">Score {r.risk_score}</span>
  </div>
  <div class="card-sub">
    {_he(r.arch)} {r.bits}-bit · {_he(r.platform)} · {r.file_size:,} B
    {'· <b class="suid-tag">SUID</b>' if r.is_suid else ''}
    {'· <b class="sgid-tag">SGID</b>' if r.is_sgid else ''}
  </div>
  <div class="card-sub">owner: {_he(r.owner)} · perms: {r.permissions}</div>
  {extra_info}
  <div class="prot-row" style="margin:6px 0">{prot_tags}</div>
  <div class="card-stats">
    <span>Total: <b>{len(r.vuln_points)}</b></span>
    <span>Confirmed: <b style="color:#30d158">{confirmed_cnt}</b></span>
    <span>High+Critical: <b style="color:#ff2d55">{high_crit_cnt}</b></span>
  </div>
  <div class="card-hash">SHA256: {r.binary_hash_sha256[:32]}…</div>
</div>
"""

    rows_html = "\n".join(report_rows)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BinSmasher CVE Audit Report — {ts}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0a0a0f;
  --bg2:#111118;
  --bg3:#18181f;
  --border:#2a2a3a;
  --text:#e8e8f0;
  --dim:#888;
  --red:#ff2d55;
  --orange:#ff9f0a;
  --yellow:#ffd60a;
  --green:#30d158;
  --blue:#0a84ff;
  --purple:#bf5af2;
  --font-mono:'JetBrains Mono',monospace;
  --font-ui:'Syne',sans-serif;
}}
body{{background:var(--bg);color:var(--text);font-family:var(--font-ui);font-size:14px;line-height:1.5;min-height:100vh}}

.header{{
  background:linear-gradient(135deg,#0a0a0f 0%,#13001f 50%,#000d1f 100%);
  border-bottom:1px solid var(--border);
  padding:2rem 2.5rem;
  position:relative;
  overflow:hidden;
}}
.header::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 60% 80% at 70% 50%,rgba(191,90,242,.12),transparent);
  pointer-events:none;
}}
.header-grid{{display:flex;align-items:center;gap:2rem;flex-wrap:wrap}}
.logo{{
  font-size:2.4rem;font-weight:800;letter-spacing:-.04em;
  background:linear-gradient(135deg,var(--red),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}}
.header-info h1{{font-size:1.05rem;font-weight:700;color:var(--text);letter-spacing:.05em;text-transform:uppercase}}
.header-info p{{color:var(--dim);font-size:.85rem;font-family:var(--font-mono)}}
.stat-pills{{display:flex;gap:.6rem;flex-wrap:wrap;margin-left:auto}}
.pill{{
  padding:.35rem .9rem;border-radius:999px;font-size:.8rem;font-weight:700;
  font-family:var(--font-mono);letter-spacing:.04em;border:1px solid;
}}
.pill-red{{border-color:var(--red);color:var(--red)}}
.pill-orange{{border-color:var(--orange);color:var(--orange)}}
.pill-green{{border-color:var(--green);color:var(--green)}}
.pill-yellow{{border-color:var(--yellow);color:var(--yellow)}}
.pill-blue{{border-color:var(--blue);color:var(--blue)}}

.main{{padding:2rem 2.5rem;max-width:1800px;margin:0 auto}}

.section-title{{
  font-size:.7rem;font-weight:700;letter-spacing:.15em;
  text-transform:uppercase;color:var(--dim);
  margin-bottom:1rem;padding-bottom:.4rem;
  border-bottom:1px solid var(--border);
}}

.cards-wrap{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2.5rem}}
.card{{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:12px;padding:1.1rem 1.3rem;min-width:260px;max-width:340px;flex:1;
  transition:border-color .2s,transform .2s;
}}
.card:hover{{border-color:var(--purple);transform:translateY(-2px)}}
.card-top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem}}
.card-name{{font-weight:700;font-size:1rem;color:var(--text)}}
.card-score{{
  font-family:var(--font-mono);font-size:.8rem;
  background:linear-gradient(135deg,var(--red),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  font-weight:700;
}}
.card-sub{{color:var(--dim);font-size:.8rem;margin:.1rem 0}}
.card-stats{{display:flex;gap:1rem;font-size:.82rem;margin-top:.5rem}}
.card-hash{{font-family:var(--font-mono);font-size:.67rem;color:#555;margin-top:.5rem;word-break:break-all}}
.suid-tag,.sgid-tag{{
  font-size:.7rem;font-weight:700;padding:.1rem .4rem;border-radius:4px;
  background:rgba(255,45,85,.2);color:var(--red);
}}

.controls{{
  background:var(--bg2);border:1px solid var(--border);border-radius:12px;
  padding:1rem 1.3rem;margin-bottom:1.5rem;
  display:flex;gap:.8rem;flex-wrap:wrap;align-items:center;
}}
.search-box{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  color:var(--text);padding:.5rem .9rem;font-family:var(--font-mono);
  font-size:.85rem;outline:none;flex:1;min-width:200px;
}}
.search-box:focus{{border-color:var(--purple)}}
.filter-sel{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  color:var(--text);padding:.5rem .9rem;font-size:.85rem;cursor:pointer;
  outline:none;
}}
.filter-sel:focus{{border-color:var(--purple)}}
.btn-reset{{
  background:transparent;border:1px solid var(--border);border-radius:8px;
  color:var(--dim);padding:.5rem 1rem;font-size:.82rem;cursor:pointer;
  transition:border-color .2s,color .2s;
}}
.btn-reset:hover{{border-color:var(--purple);color:var(--text)}}
.count-label{{
  font-family:var(--font-mono);font-size:.8rem;color:var(--dim);margin-left:auto;
}}

.tbl-wrap{{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:12px;overflow:hidden;
}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
thead tr{{background:var(--bg3);border-bottom:2px solid var(--border)}}
th{{
  padding:.75rem 1rem;text-align:left;font-size:.68rem;
  letter-spacing:.1em;text-transform:uppercase;color:var(--dim);
  font-weight:700;cursor:pointer;user-select:none;white-space:nowrap;
}}
th:hover{{color:var(--text)}}
th .sort-arrow{{opacity:.35;margin-left:.3rem}}
tbody tr{{border-bottom:1px solid var(--border);transition:background .15s}}
tbody tr:hover{{background:rgba(191,90,242,.04)}}
tbody tr.hidden-row{{display:none}}
td{{padding:.7rem 1rem;vertical-align:top}}

.badge-id{{
  font-family:var(--font-mono);font-size:.72rem;background:var(--bg3);
  border:1px solid var(--border);border-radius:6px;padding:.15rem .4rem;
  color:var(--dim);
}}
.badge-conf{{
  display:inline-block;font-size:.72rem;font-weight:700;padding:.2rem .6rem;
  border-radius:6px;border:1px solid var(--c,#888);color:var(--c,#888);
  font-family:var(--font-mono);
}}
.cat-tag{{
  font-size:.72rem;background:rgba(10,132,255,.12);
  color:var(--blue);padding:.2rem .5rem;border-radius:6px;
  border:1px solid rgba(10,132,255,.25);
}}
.cwe-link{{
  color:var(--purple);text-decoration:none;font-family:var(--font-mono);font-size:.8rem;
}}
.cwe-link:hover{{text-decoration:underline}}
.fn-name{{color:var(--yellow);font-size:.82rem}}
.addr{{color:var(--dim);font-family:var(--font-mono);font-size:.75rem}}
.cvss-badge{{
  display:inline-block;font-weight:700;font-family:var(--font-mono);
  font-size:.85rem;color:var(--c,#888);
}}
.sev-badge{{
  font-size:.72rem;font-weight:700;padding:.2rem .55rem;border-radius:6px;
  background:color-mix(in srgb,var(--c,#888) 15%,transparent);
  color:var(--c,#888);border:1px solid color-mix(in srgb,var(--c,#888) 35%,transparent);
}}
.meta{{color:var(--dim);font-size:.72rem;font-family:var(--font-mono);margin-top:.2rem}}
.prot-row{{display:flex;gap:.3rem;flex-wrap:wrap}}
.p{{
  font-size:.65rem;font-weight:700;padding:.1rem .35rem;
  border-radius:4px;font-family:var(--font-mono);
}}
.p-ok{{background:rgba(48,209,88,.15);color:var(--green);border:1px solid rgba(48,209,88,.3)}}
.p-no{{background:rgba(255,45,85,.15);color:var(--red);border:1px solid rgba(255,45,85,.3)}}
.p-partial{{background:rgba(255,159,10,.15);color:var(--orange);border:1px solid rgba(255,159,10,.3)}}

.ptag{{font-size:.7rem;font-weight:700;padding:.15rem .4rem;border-radius:5px;font-family:var(--font-mono)}}
.ptok{{background:rgba(48,209,88,.1);color:var(--green);border:1px solid rgba(48,209,88,.25)}}
.ptno{{background:rgba(255,45,85,.1);color:var(--red);border:1px solid rgba(255,45,85,.25)}}
.ptpart{{background:rgba(255,159,10,.1);color:var(--orange);border:1px solid rgba(255,159,10,.25)}}

.ev-btn{{
  background:transparent;border:1px solid var(--border);border-radius:6px;
  color:var(--dim);padding:.3rem .6rem;font-size:.75rem;cursor:pointer;
  transition:all .15s;white-space:nowrap;
}}
.ev-btn:hover,.ev-btn.open{{border-color:var(--purple);color:var(--purple)}}
.ev-panel{{
  margin-top:.6rem;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;padding:.7rem .9rem;
}}
.ev-item{{
  font-family:var(--font-mono);font-size:.73rem;color:var(--dim);
  padding:.2rem 0;border-bottom:1px solid var(--bg3);
}}
.ev-item:last-child{{border-bottom:none}}
.mitigation{{
  font-size:.77rem;color:var(--green);margin-top:.5rem;
  padding-top:.4rem;border-top:1px solid var(--border);
}}

.chart-bar-wrap{{display:flex;gap:1rem;margin-bottom:2.5rem;flex-wrap:wrap}}
.chart-box{{
  background:var(--bg2);border:1px solid var(--border);border-radius:12px;
  padding:1.2rem 1.5rem;flex:1;min-width:220px;
}}
.chart-label{{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);margin-bottom:.8rem}}
.bar-item{{display:flex;align-items:center;gap:.7rem;margin-bottom:.45rem}}
.bar-key{{font-size:.78rem;color:var(--dim);width:90px;text-align:right;flex-shrink:0}}
.bar-track{{flex:1;background:var(--bg3);border-radius:3px;height:8px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:3px;transition:width .4s ease}}
.bar-val{{font-size:.78rem;font-family:var(--font-mono);color:var(--text);width:28px}}

.footer{{
  text-align:center;padding:2rem;border-top:1px solid var(--border);
  color:var(--dim);font-size:.78rem;font-family:var(--font-mono);
}}
</style>
</head>
<body>

<header class="header">
  <div class="header-grid">
    <div class="logo">&#x2B21; BS</div>
    <div class="header-info">
      <h1>BinSmasher CVE Audit Report</h1>
      <p>Generated: {ts} &middot; Static binary analysis &middot; Responsible disclosure</p>
    </div>
    <div class="stat-pills">
      <span class="pill pill-blue">Binaries: {len(reports)}</span>
      <span class="pill pill-blue">Findings: {len(all_vps)}</span>
      <span class="pill pill-green">Confirmed: {total_confirmed}</span>
      <span class="pill pill-yellow">Probable: {total_probable}</span>
      <span class="pill pill-red">Critical: {total_critical}</span>
      <span class="pill pill-orange">High: {total_high}</span>
    </div>
  </div>
</header>

<main class="main">

  <div class="section-title">Overview</div>
  <div class="chart-bar-wrap">
    {_bar_chart("Severity Distribution", [
        ("Critical", total_critical, "#ff2d55", len(all_vps)),
        ("High",     total_high,     "#ff9f0a", len(all_vps)),
        ("Medium",   sum(1 for v in all_vps if v.severity=="Medium"), "#ffd60a", len(all_vps)),
        ("Low",      sum(1 for v in all_vps if v.severity=="Low"),    "#30d158", len(all_vps)),
    ])}
    {_bar_chart("Confidence Levels", [
        ("CONFIRMED",   total_confirmed,  "#30d158", len(all_vps)),
        ("PROBABLE",    total_probable,   "#ffd60a", len(all_vps)),
        ("UNCONFIRMED", sum(1 for v in all_vps if v.confidence=="UNCONFIRMED"), "#636366", len(all_vps)),
    ])}
    {_bar_chart("Top Categories", sorted(
        [(cat, sum(1 for v in all_vps if v.category==cat), "#0a84ff", max(1,len(all_vps)))
         for cat in dict.fromkeys(v.category for v in all_vps)],
        key=lambda x: -x[1]
    )[:6])}
  </div>

  <div class="section-title">Audited Binaries</div>
  <div class="cards-wrap">{cards_html}</div>

  <div class="section-title">Vulnerability Findings</div>
  <div class="controls">
    <input class="search-box" type="text" id="search" placeholder="&#x1F50D;  Search binary, function, CWE, category&hellip;" oninput="applyFilters()">
    <select class="filter-sel" id="fConf" onchange="applyFilters()">
      <option value="">All Confidence</option>
      <option value="CONFIRMED">CONFIRMED</option>
      <option value="PROBABLE">PROBABLE</option>
      <option value="UNCONFIRMED">UNCONFIRMED</option>
    </select>
    <select class="filter-sel" id="fSev" onchange="applyFilters()">
      <option value="">All Severity</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <select class="filter-sel" id="fCat" onchange="applyFilters()">
      <option value="">All Categories</option>
      {"".join(f'<option value="{c}">{c}</option>' for c in sorted(set(v.category for v in all_vps)))}
    </select>
    <select class="filter-sel" id="fBin" onchange="applyFilters()">
      <option value="">All Binaries</option>
      {"".join(f'<option value="{_he(r.binary_name)}">{_he(r.binary_name)}</option>' for r in reports)}
    </select>
    <button class="btn-reset" onclick="resetFilters()">Reset</button>
    <span class="count-label" id="rowCount">{len(all_vps)} findings</span>
  </div>

  <div class="tbl-wrap">
    <table id="mainTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)">ID <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(1)">Confidence <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(2)">Binary <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(3)">Category <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(4)">CWE <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(5)">Function <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(6)">Address(es) <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(7)">CVSS <span class="sort-arrow">&#x2195;</span></th>
          <th onclick="sortTable(8)">Severity <span class="sort-arrow">&#x22195;</span></th>
          <th>Protections</th>
          <th>Evidence / Fix</th>
        </tr>
      </thead>
      <tbody id="tableBody">
        {rows_html}
      </tbody>
    </table>
  </div>
</main>

<footer class="footer">
  BinSmasher CVE Auditor v3 &middot; Static analysis only &middot; No exploitation &middot; Responsible disclosure
</footer>

<script>
function applyFilters() {{
  const q    = document.getElementById('search').value.toLowerCase();
  const conf = document.getElementById('fConf').value;
  const sev  = document.getElementById('fSev').value;
  const cat  = document.getElementById('fCat').value;
  const bin  = document.getElementById('fBin').value;
  const rows = document.querySelectorAll('#tableBody tr');
  let visible = 0;
  rows.forEach(row => {{
    const txt  = row.textContent.toLowerCase();
    const show = (
      (!q    || txt.includes(q)) &&
      (!conf || row.dataset.confidence === conf) &&
      (!sev  || row.dataset.severity   === sev) &&
      (!cat  || row.dataset.category   === cat) &&
      (!bin  || row.dataset.binary     === bin)
    );
    row.classList.toggle('hidden-row', !show);
    if (show) visible++;
  }});
  document.getElementById('rowCount').textContent = visible + ' findings';
}}

function resetFilters() {{
  ['search','fConf','fSev','fCat','fBin'].forEach(id => {{
    const el = document.getElementById(id);
    if (el.tagName === 'INPUT') el.value = '';
    else el.value = '';
  }});
  applyFilters();
}}

function toggleEvidence(btn) {{
  const panel = btn.nextElementSibling;
  const open  = panel.style.display === 'none';
  panel.style.display = open ? 'block' : 'none';
  btn.textContent = open ? '▲ Evidence' : '▼ Evidence';
  btn.classList.toggle('open', open);
}}

let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById('tableBody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  sortDir[col] = !sortDir[col];
  rows.sort((a, b) => {{
    const at = a.cells[col]?.textContent.trim() || '';
    const bt = b.cells[col]?.textContent.trim() || '';
    const an = parseFloat(at), bn = parseFloat(bt);
    if (!isNaN(an) && !isNaN(bn)) return sortDir[col] ? an-bn : bn-an;
    return sortDir[col] ? at.localeCompare(bt) : bt.localeCompare(at);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""

    return html