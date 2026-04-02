"""
SUNGLASSES Daily Protection Report — Proof it works.

Logs every scan locally. Generates daily reports showing what was blocked.
Zero cloud. Zero data sent anywhere. Free. Forever.

Usage:
    # In your code — wrap the engine with logging
    from sunglasses.reporter import ProtectedEngine
    engine = ProtectedEngine()  # drop-in replacement for SunglassesEngine
    result = engine.scan("some text")  # scans AND logs automatically

    # Generate report
    from sunglasses.reporter import generate_report
    report = generate_report()  # today's report
    print(report)
"""

import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .engine import SunglassesEngine


def _log_dir() -> Path:
    """Get or create the local log directory."""
    d = Path.home() / ".sunglasses" / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _log_file(date: Optional[str] = None) -> Path:
    """Get the log file for a given date (default: today)."""
    if date is None:
        date = datetime.now().strftime("%Y-%m-%d")
    return _log_dir() / f"scans-{date}.jsonl"


class ProtectedEngine(SunglassesEngine):
    """Drop-in replacement for SunglassesEngine that logs every scan locally."""

    def scan(self, text: str, channel: str = "message") -> "ScanResult":
        result = super().scan(text, channel=channel)

        # Log to local file — never sent anywhere
        entry = {
            "ts": datetime.now().isoformat(),
            "event_id": result.event_id,
            "decision": result.decision,
            "is_clean": result.is_clean,
            "severity": result.severity,
            "channel": channel,
            "latency_ms": result.latency_ms,
            "findings_count": len(result.findings),
            "categories": [f["category"] for f in result.findings],
            "finding_names": [f["name"] for f in result.findings],
        }
        # NO raw input logged — privacy first
        try:
            with open(_log_file(), "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass  # never crash the scan because of logging

        return result


def generate_report(date: Optional[str] = None, as_html: bool = False) -> str:
    """Generate a daily protection report from local scan logs."""
    if date is None:
        date = datetime.now().strftime("%Y-%m-%d")

    log_path = _log_file(date)

    if not log_path.exists():
        return f"No scan data for {date}. Run some scans first!"

    # Parse log entries
    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not entries:
        return f"No scan data for {date}."

    # Calculate stats
    total = len(entries)
    blocked = sum(1 for e in entries if e["decision"] == "block")
    quarantined = sum(1 for e in entries if e["decision"] == "quarantine")
    clean = sum(1 for e in entries if e["is_clean"])
    redacted = sum(1 for e in entries if e["decision"] == "allow_redacted")

    # Category breakdown
    all_categories = []
    for e in entries:
        all_categories.extend(e.get("categories", []))
    category_counts = {}
    for c in all_categories:
        category_counts[c] = category_counts.get(c, 0) + 1

    # Average latency
    avg_latency = sum(e["latency_ms"] for e in entries) / total

    # Threat timeline
    threats = [e for e in entries if not e["is_clean"]]

    if as_html:
        return _generate_html_report(date, total, blocked, quarantined, clean,
                                      redacted, category_counts, avg_latency, threats)

    # Terminal report
    lines = []
    lines.append("")
    lines.append("  ╔══════════════════════════════════════════════════╗")
    lines.append("  ║       SUNGLASSES — Daily Protection Report      ║")
    lines.append("  ╚══════════════════════════════════════════════════╝")
    lines.append(f"  Date: {date}")
    lines.append("")
    lines.append(f"  Scans today:        {total}")
    lines.append(f"  Attacks blocked:    {blocked}")
    lines.append(f"  Quarantined:        {quarantined}")
    lines.append(f"  Clean passes:       {clean}")
    if redacted:
        lines.append(f"  Redacted & passed:  {redacted}")
    lines.append(f"  Avg scan time:      {avg_latency:.2f}ms")
    lines.append("")

    if category_counts:
        lines.append("  Threats by category:")
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 20)
            lines.append(f"    {cat:<25s} {count:>3d}  {bar}")
        lines.append("")

    if threats:
        lines.append("  Attack log:")
        for t in threats[-10:]:  # last 10 threats
            ts = t["ts"].split("T")[1][:8]
            names = ", ".join(t.get("finding_names", ["unknown"]))
            lines.append(f"    [{ts}] {t['decision'].upper():>10s} — {names}")
        if len(threats) > 10:
            lines.append(f"    ... and {len(threats) - 10} more")
        lines.append("")

    lines.append(f"  Without SUNGLASSES: {blocked + quarantined} attack(s)")
    lines.append(f"  would have reached your agent undetected.")
    lines.append("")
    lines.append("  Data sent to anyone: 0 bytes. Everything stays local.")
    lines.append("  Daily reports. Free. Forever.")
    lines.append("")

    return "\n".join(lines)


def _generate_html_report(date, total, blocked, quarantined, clean,
                           redacted, category_counts, avg_latency, threats):
    """Generate a cybersecurity-themed HTML report."""
    # Protection score (percentage of scans that were clean)
    protection_score = round((clean / total) * 100) if total > 0 else 100
    threat_count = blocked + quarantined
    score_color = "#00ff88" if protection_score >= 90 else "#ffcc00" if protection_score >= 70 else "#ff4444"

    # Threat log rows
    threat_rows = ""
    for t in threats[-20:]:
        ts = t["ts"].split("T")[1][:8]
        names = ", ".join(t.get("finding_names", ["unknown"]))
        sev = t.get("severity", "high")
        if t["decision"] == "block":
            status_html = '<span class="badge badge-red">NEUTRALIZED</span>'
        else:
            status_html = '<span class="badge badge-yellow">QUARANTINED</span>'
        sev_html = f'<span class="badge badge-{"red" if sev in ("critical","high") else "yellow"}">{sev.upper()}</span>'
        threat_rows += f'''<div class="threat-row">
          <div class="threat-time">{ts}</div>
          <div class="threat-info"><div class="threat-name">{names}</div><div class="threat-meta">{status_html} {sev_html}</div></div>
        </div>\n'''

    # Category bars
    max_count = max(category_counts.values()) if category_counts else 1
    cat_rows = ""
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        pct = round((count / max_count) * 100)
        cat_display = cat.replace("_", " ").title()
        cat_rows += f'''<div class="cat-row">
          <span class="cat-name">{cat_display}</span>
          <div class="cat-bar-bg"><div class="cat-bar" style="width:{pct}%"></div></div>
          <span class="cat-count">{count}</span>
        </div>\n'''

    return f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>SUNGLASSES — Threat Report {date}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background:#050508; color:#c0c8d0;
    font-family:'SF Mono','Fira Code','Cascadia Code',monospace;
    padding:0; min-height:100vh;
  }}
  .scanline {{
    position:fixed; top:0; left:0; right:0; bottom:0; pointer-events:none; z-index:100;
    background: repeating-linear-gradient(0deg, rgba(0,255,100,0.015) 0px, transparent 1px, transparent 2px);
  }}
  .container {{ max-width:760px; margin:0 auto; padding:40px 24px; position:relative; z-index:1; }}

  /* Header */
  .header {{ border-bottom:1px solid #0f2; padding-bottom:24px; margin-bottom:32px; }}
  .header-top {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }}
  .logo {{ font-size:13px; letter-spacing:4px; color:#0f2; font-weight:700; }}
  .status {{ font-size:11px; letter-spacing:2px; color:#0f2; }}
  .status-dot {{ display:inline-block; width:6px; height:6px; border-radius:50%; background:#0f2; margin-right:6px; animation:blink 2s infinite; }}
  @keyframes blink {{ 0%,100%{{opacity:1}} 50%{{opacity:0.3}} }}
  .title {{ font-size:22px; font-weight:700; color:#fff; letter-spacing:-0.5px; font-family:-apple-system,sans-serif; }}
  .subtitle {{ font-size:13px; color:#556; margin-top:4px; }}

  /* Score ring */
  .score-section {{ text-align:center; margin:32px 0; }}
  .score-ring {{ position:relative; width:160px; height:160px; margin:0 auto 12px; }}
  .score-ring svg {{ transform:rotate(-90deg); }}
  .score-ring .bg {{ fill:none; stroke:#111; stroke-width:8; }}
  .score-ring .fg {{ fill:none; stroke:{score_color}; stroke-width:8; stroke-linecap:round;
    stroke-dasharray:{protection_score * 4.4} 440; transition:stroke-dasharray 1s; }}
  .score-num {{ position:absolute; top:50%; left:50%; transform:translate(-50%,-50%);
    font-size:42px; font-weight:800; color:{score_color}; font-family:-apple-system,sans-serif; }}
  .score-label {{ font-size:12px; color:#556; letter-spacing:2px; text-transform:uppercase; }}

  /* Stat grid */
  .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:32px 0; }}
  .stat {{ background:#0a0c10; border:1px solid #1a1e28; border-radius:8px; padding:16px; text-align:center; }}
  .stat-num {{ font-size:32px; font-weight:800; font-family:-apple-system,sans-serif; }}
  .stat-label {{ font-size:10px; color:#556; letter-spacing:2px; text-transform:uppercase; margin-top:4px; }}
  .stat-green .stat-num {{ color:#0f2; }}
  .stat-red .stat-num {{ color:#f44; }}
  .stat-yellow .stat-num {{ color:#fc0; }}
  .stat-white .stat-num {{ color:#fff; }}

  /* Section headers */
  .section-head {{ font-size:11px; letter-spacing:3px; text-transform:uppercase; color:#0f2;
    border-bottom:1px solid #1a1e28; padding-bottom:8px; margin:32px 0 16px; }}

  /* Category bars */
  .cat-row {{ display:flex; align-items:center; gap:12px; margin:8px 0; }}
  .cat-name {{ min-width:160px; font-size:12px; color:#889; }}
  .cat-bar-bg {{ flex:1; height:6px; background:#111; border-radius:3px; overflow:hidden; }}
  .cat-bar {{ height:100%; background:linear-gradient(90deg,#f44,#fc0); border-radius:3px;
    animation:barGrow 0.8s ease-out; }}
  @keyframes barGrow {{ from{{width:0}} }}
  .cat-count {{ font-size:13px; color:#f44; font-weight:700; min-width:24px; text-align:right; }}

  /* Threat log */
  .threat-row {{ display:flex; gap:12px; padding:12px 0; border-bottom:1px solid #0e1018; align-items:flex-start; }}
  .threat-time {{ font-size:12px; color:#334; min-width:60px; padding-top:2px; }}
  .threat-name {{ font-size:14px; color:#ddd; font-family:-apple-system,sans-serif; }}
  .threat-meta {{ margin-top:4px; display:flex; gap:6px; }}

  /* Badges */
  .badge {{ display:inline-block; font-size:9px; letter-spacing:1.5px; padding:3px 8px;
    border-radius:3px; font-weight:700; text-transform:uppercase; }}
  .badge-red {{ background:rgba(255,68,68,0.15); color:#f66; border:1px solid rgba(255,68,68,0.3); }}
  .badge-yellow {{ background:rgba(255,200,0,0.1); color:#fc0; border:1px solid rgba(255,200,0,0.2); }}
  .badge-green {{ background:rgba(0,255,100,0.1); color:#0f2; border:1px solid rgba(0,255,100,0.2); }}

  /* Speed */
  .speed {{ text-align:center; margin:24px 0; padding:16px; background:#0a0c10; border:1px solid #1a1e28; border-radius:8px; }}
  .speed-num {{ font-size:28px; font-weight:800; color:#0f2; font-family:-apple-system,sans-serif; }}
  .speed-label {{ font-size:11px; color:#556; letter-spacing:2px; margin-top:2px; }}

  /* Impact box */
  .impact {{ background:linear-gradient(135deg, rgba(255,68,68,0.05), rgba(255,68,68,0.02));
    border:1px solid rgba(255,68,68,0.2); border-radius:8px; padding:20px; margin:32px 0; text-align:center; }}
  .impact-num {{ font-size:48px; font-weight:800; color:#f44; font-family:-apple-system,sans-serif; }}
  .impact-label {{ font-size:13px; color:#a66; margin-top:4px; }}

  /* Footer */
  .footer {{ margin-top:40px; padding-top:20px; border-top:1px solid #1a1e28; text-align:center; }}
  .footer-line {{ font-size:12px; color:#334; margin:4px 0; }}
  .footer-line strong {{ color:#0f2; }}
  .footer-brand {{ font-size:11px; letter-spacing:4px; color:#1a2; margin-top:16px; }}

  @media(max-width:600px) {{
    .stats {{ grid-template-columns:repeat(2,1fr); }}
    .cat-name {{ min-width:100px; }}
    .score-ring {{ width:120px; height:120px; }}
    .score-num {{ font-size:32px; }}
  }}
</style></head><body>
<div class="scanline"></div>
<div class="container">
  <div class="header">
    <div class="header-top">
      <div class="logo">SUNGLASSES</div>
      <div class="status"><span class="status-dot"></span>PROTECTION ACTIVE</div>
    </div>
    <div class="title">Threat Intelligence Report</div>
    <div class="subtitle">{date} &middot; Generated locally &middot; 0 bytes transmitted</div>
  </div>

  <div class="score-section">
    <div class="score-ring">
      <svg viewBox="0 0 160 160" width="160" height="160">
        <circle class="bg" cx="80" cy="80" r="70"/>
        <circle class="fg" cx="80" cy="80" r="70"/>
      </svg>
      <div class="score-num">{protection_score}%</div>
    </div>
    <div class="score-label">Protection Score</div>
  </div>

  <div class="stats">
    <div class="stat stat-white"><div class="stat-num">{total}</div><div class="stat-label">Scans</div></div>
    <div class="stat stat-red"><div class="stat-num">{blocked}</div><div class="stat-label">Blocked</div></div>
    <div class="stat stat-yellow"><div class="stat-num">{quarantined}</div><div class="stat-label">Quarantined</div></div>
    <div class="stat stat-green"><div class="stat-num">{clean}</div><div class="stat-label">Clean</div></div>
  </div>

  <div class="speed">
    <div class="speed-num">{avg_latency:.2f}ms</div>
    <div class="speed-label">Average Scan Time</div>
  </div>

  {"<div class='section-head'>Threat Categories Detected</div>" + cat_rows if cat_rows else ""}

  {"<div class='section-head'>Incident Log</div>" + threat_rows if threat_rows else ""}

  <div class="impact">
    <div class="impact-num">{threat_count}</div>
    <div class="impact-label">attack{"s" if threat_count != 1 else ""} would have reached your agent without SUNGLASSES</div>
  </div>


  <div class="footer">
    <div class="footer-line">Data sent to anyone: <strong>0 bytes</strong></div>
    <div class="footer-line">Everything stays on <strong>your machine</strong></div>
    <div class="footer-line">Daily reports. <strong>Free. Forever.</strong></div>
    <div class="footer-brand">SUNGLASSES</div>
  </div>
</div>
</body></html>'''
