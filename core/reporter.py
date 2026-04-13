import json
import os
import re
from datetime import datetime
from jinja2 import Environment
from core.utils import print_info

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="author" content="Aditya Singh">
<meta name="generator" content="WebVulnScanner by Aditya Singh — github.com/Adityasiig">
<title>Scan Report — {{ target }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:       #0d0d0d;
  --surface:  #161616;
  --surface2: #1c1c1c;
  --border:   #2a2a2a;
  --border2:  #333;
  --text:     #e8e8e8;
  --text2:    #999;
  --text3:    #555;
  --cr: #e5534b; --cr-bg: #e5534b14; --cr-bd: #e5534b30;
  --hi: #e8813a; --hi-bg: #e8813a14; --hi-bd: #e8813a30;
  --me: #c9a227; --me-bg: #c9a22714; --me-bd: #c9a22730;
  --lo: #3fb950; --lo-bg: #3fb95014; --lo-bd: #3fb95030;
  --in: #484f58; --in-bg: #484f5814; --in-bd: #484f5830;
  --blue: #4493f8;
  --r: 8px;
}
html { scroll-behavior: smooth; }
body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; min-height: 100vh; }
a { color: var(--blue); text-decoration: none; }
::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: var(--bg); } ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

/* Layout */
.layout { display: flex; min-height: 100vh; }
.sidebar { width: 220px; flex-shrink: 0; background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; position: sticky; top: 0; height: 100vh; overflow-y: auto; }
.main { flex: 1; min-width: 0; padding: 32px 40px; max-width: 1200px; }

/* Sidebar */
.sb-logo { padding: 20px 20px 16px; border-bottom: 1px solid var(--border); }
.sb-logo-mark { display: flex; align-items: center; gap: 9px; }
.sb-logo-icon { width: 28px; height: 28px; background: var(--surface2); border: 1px solid var(--border2); border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 14px; }
.sb-logo-name { font-size: 13px; font-weight: 600; color: var(--text); letter-spacing: -0.2px; }
.sb-logo-sub { font-size: 11px; color: var(--text3); margin-top: 1px; }
.sb-section { padding: 12px 0 4px; }
.sb-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--text3); padding: 0 16px 6px; }
.sb-item { display: flex; align-items: center; gap: 8px; padding: 7px 16px; font-size: 12.5px; color: var(--text2); cursor: pointer; border-left: 2px solid transparent; transition: all .15s; text-decoration: none; }
.sb-item:hover { color: var(--text); background: var(--surface2); }
.sb-item.active { color: var(--text); background: var(--surface2); border-left-color: var(--blue); }
.sb-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.sb-count { margin-left: auto; font-size: 11px; font-weight: 600; color: var(--text3); background: var(--surface2); border: 1px solid var(--border); padding: 1px 6px; border-radius: 10px; }
.sb-count.cr { color: var(--cr); background: var(--cr-bg); border-color: var(--cr-bd); }
.sb-count.hi { color: var(--hi); background: var(--hi-bg); border-color: var(--hi-bd); }
.sb-count.me { color: var(--me); background: var(--me-bg); border-color: var(--me-bd); }
.sb-foot { margin-top: auto; border-top: 1px solid var(--border); }
.sb-author { padding: 14px 16px; display: flex; align-items: center; gap: 10px; }
.sb-avatar { width: 30px; height: 30px; border-radius: 50%; background: linear-gradient(135deg, #4493f8, #a78bfa); display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; color: #fff; flex-shrink: 0; letter-spacing: -0.5px; }
.sb-author-info { min-width: 0; }
.sb-author-name { font-size: 12px; font-weight: 600; color: var(--text); white-space: nowrap; }
.sb-author-role { font-size: 10px; color: var(--text3); margin-top: 1px; }
.sb-links { padding: 0 12px 14px; display: flex; flex-direction: column; gap: 2px; }
.sb-link-item { display: flex; align-items: center; gap: 7px; padding: 5px 6px; border-radius: 5px; font-size: 11px; color: var(--text3); text-decoration: none; transition: all .15s; }
.sb-link-item:hover { color: var(--text); background: var(--surface2); }
.sb-link-item svg { flex-shrink: 0; opacity: .6; }
.sb-meta { padding: 0 16px 14px; font-size: 10px; color: var(--text3); line-height: 1.8; border-top: 1px solid var(--border); padding-top: 10px; }

/* Page header */
.page-header { margin-bottom: 32px; }
.page-eyebrow { font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 1px; color: var(--text3); margin-bottom: 8px; }
.page-title { font-size: 22px; font-weight: 600; letter-spacing: -0.5px; color: var(--text); }
.page-url { font-size: 12px; color: var(--text2); margin-top: 4px; font-family: 'JetBrains Mono', monospace; }
.page-meta { display: flex; gap: 24px; margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
.meta-item { display: flex; flex-direction: column; gap: 2px; }
.meta-label { font-size: 10px; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); font-weight: 600; }
.meta-value { font-size: 13px; font-weight: 500; color: var(--text); }

/* Risk badge */
.risk-badge { display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; letter-spacing: .3px; border: 1px solid; }
.risk-CRITICAL { color: var(--cr); background: var(--cr-bg); border-color: var(--cr-bd); }
.risk-HIGH     { color: var(--hi); background: var(--hi-bg); border-color: var(--hi-bd); }
.risk-MEDIUM   { color: var(--me); background: var(--me-bg); border-color: var(--me-bd); }
.risk-LOW      { color: var(--lo); background: var(--lo-bg); border-color: var(--lo-bd); }
.risk-NONE     { color: var(--lo); background: var(--lo-bg); border-color: var(--lo-bd); }

/* Stat grid */
.stat-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 28px; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); padding: 18px 16px; position: relative; overflow: hidden; }
.stat-card::before { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 2px; }
.stat-cr::before { background: var(--cr); } .stat-hi::before { background: var(--hi); }
.stat-me::before { background: var(--me); } .stat-lo::before { background: var(--lo); }
.stat-in::before { background: var(--in); }
.stat-num { font-size: 28px; font-weight: 700; letter-spacing: -1px; line-height: 1; }
.stat-cr .stat-num { color: var(--cr); } .stat-hi .stat-num { color: var(--hi); }
.stat-me .stat-num { color: var(--me); } .stat-lo .stat-num { color: var(--lo); }
.stat-in .stat-num { color: var(--in); }
.stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); font-weight: 600; margin-top: 6px; }

/* Overview row */
.overview-row { display: grid; grid-template-columns: 1fr 200px; gap: 16px; margin-bottom: 28px; }
.ov-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); padding: 20px; }
.ov-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); margin-bottom: 16px; }
.bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.bar-label { font-size: 12px; color: var(--text2); width: 64px; flex-shrink: 0; }
.bar-track { flex: 1; height: 4px; background: var(--surface2); border-radius: 2px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 2px; transition: width .6s cubic-bezier(.4,0,.2,1); width: 0; }
.bar-val { font-size: 12px; font-weight: 600; color: var(--text2); width: 20px; text-align: right; }
.chart-wrap { display: flex; align-items: center; justify-content: center; height: 160px; }

/* Toolbar */
.toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
.search-input { flex: 1; min-width: 200px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 7px 12px; color: var(--text); font-size: 13px; font-family: 'Inter', sans-serif; outline: none; transition: border-color .15s; }
.search-input:focus { border-color: var(--border2); }
.search-input::placeholder { color: var(--text3); }
.filter-btn { padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--text2); font-size: 12px; font-family: 'Inter', sans-serif; cursor: pointer; transition: all .15s; white-space: nowrap; }
.filter-btn:hover { border-color: var(--border2); color: var(--text); }
.filter-btn.on { border-color: var(--blue); color: var(--blue); background: #4493f810; }
.filter-btn.on-cr { border-color: var(--cr-bd); color: var(--cr); background: var(--cr-bg); }
.filter-btn.on-hi { border-color: var(--hi-bd); color: var(--hi); background: var(--hi-bg); }
.filter-btn.on-me { border-color: var(--me-bd); color: var(--me); background: var(--me-bg); }
.filter-btn.on-lo { border-color: var(--lo-bd); color: var(--lo); background: var(--lo-bg); }
.tb-sep { width: 1px; height: 20px; background: var(--border); margin: 0 2px; }
.tb-btn { padding: 6px 10px; border-radius: 6px; border: 1px solid var(--border); background: transparent; color: var(--text3); font-size: 11px; font-family: 'Inter', sans-serif; cursor: pointer; transition: all .15s; }
.tb-btn:hover { color: var(--text); border-color: var(--border2); }

/* Section header */
.sec-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
.sec-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.sec-dot.cr { background: var(--cr); } .sec-dot.hi { background: var(--hi); }
.sec-dot.me { background: var(--me); } .sec-dot.lo { background: var(--lo); }
.sec-dot.in { background: var(--in); }
.sec-title { font-size: 13px; font-weight: 600; }
.sec-count { margin-left: auto; font-size: 11px; color: var(--text3); }
.sec-group { margin-bottom: 28px; }

/* Finding card */
.f-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); margin-bottom: 6px; overflow: hidden; transition: border-color .15s; border-left: 3px solid; }
.f-card:hover { border-color: var(--border2); }
.f-card.sev-CRITICAL { border-left-color: var(--cr); }
.f-card.sev-HIGH     { border-left-color: var(--hi); }
.f-card.sev-MEDIUM   { border-left-color: var(--me); }
.f-card.sev-LOW      { border-left-color: var(--lo); }
.f-card.sev-INFO     { border-left-color: var(--in); }
.f-card.hidden { display: none; }
.f-head { width: 100%; text-align: left; background: none; border: none; padding: 13px 16px; cursor: pointer; display: flex; align-items: center; gap: 10px; color: var(--text); font-family: 'Inter', sans-serif; transition: background .12s; }
.f-head:hover { background: var(--surface2); }
.f-module { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); background: var(--surface2); border: 1px solid var(--border); padding: 2px 7px; border-radius: 4px; flex-shrink: 0; }
.f-title { font-size: 13px; font-weight: 500; flex: 1; text-align: left; }
.f-pill { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; border: 1px solid; letter-spacing: .3px; flex-shrink: 0; }
.f-pill.CRITICAL { color: var(--cr); background: var(--cr-bg); border-color: var(--cr-bd); }
.f-pill.HIGH     { color: var(--hi); background: var(--hi-bg); border-color: var(--hi-bd); }
.f-pill.MEDIUM   { color: var(--me); background: var(--me-bg); border-color: var(--me-bd); }
.f-pill.LOW      { color: var(--lo); background: var(--lo-bg); border-color: var(--lo-bd); }
.f-pill.INFO     { color: var(--in); background: var(--in-bg); border-color: var(--in-bd); }
.f-chevron { color: var(--text3); font-size: 10px; transition: transform .2s; flex-shrink: 0; }
.f-card.open .f-chevron { transform: rotate(180deg); }

/* Card body */
.f-body { display: none; border-top: 1px solid var(--border); padding: 16px; }
.f-card.open .f-body { display: block; }
.f-desc { font-size: 13px; color: var(--text2); margin-bottom: 14px; line-height: 1.6; }
.f-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }
.f-field { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; }
.f-field.full { grid-column: 1 / -1; }
.f-field-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); margin-bottom: 4px; }
.f-field-value { font-size: 12px; color: var(--text); font-family: 'JetBrains Mono', monospace; word-break: break-all; }
.f-field-value.url-val { color: var(--blue); }
.f-field-value.ev-val  { color: var(--hi); }
.f-field-value.pm-val  { color: #a78bfa; }

/* Payload block */
.payload-block { position: relative; margin-bottom: 12px; }
.payload-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); margin-bottom: 6px; }
.payload-code { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 40px 10px 12px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #e8813a; word-break: break-all; }
.copy-btn { position: absolute; top: 24px; right: 8px; background: var(--surface2); border: 1px solid var(--border); color: var(--text3); padding: 3px 8px; border-radius: 4px; cursor: pointer; font-size: 10px; font-family: 'Inter', sans-serif; transition: all .15s; }
.copy-btn:hover { color: var(--text); border-color: var(--border2); }
.copy-btn.ok { color: var(--lo); border-color: var(--lo-bd); }

/* Fix box */
.fix-box { background: #0d1a0f; border: 1px solid var(--lo-bd); border-radius: 6px; padding: 10px 12px; margin-bottom: 12px; }
.fix-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--lo); margin-bottom: 4px; }
.fix-value { font-size: 12px; color: #86efac; font-family: 'JetBrains Mono', monospace; }

/* Exploit section */
.exp-toggle { display: flex; align-items: center; gap: 8px; width: 100%; text-align: left; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 9px 12px; cursor: pointer; font-size: 12px; font-weight: 500; color: var(--text2); font-family: 'Inter', sans-serif; transition: all .15s; margin-top: 4px; }
.exp-toggle:hover { color: var(--text); border-color: var(--border2); }
.exp-toggle-arrow { margin-left: auto; font-size: 10px; transition: transform .2s; }
.exp-toggle.open { color: var(--text); border-color: var(--border2); border-bottom-left-radius: 0; border-bottom-right-radius: 0; }
.exp-toggle.open .exp-toggle-arrow { transform: rotate(180deg); }
.exp-body { display: none; background: var(--bg); border: 1px solid var(--border); border-top: none; border-radius: 0 0 6px 6px; padding: 14px; }
.exp-what { font-size: 12px; color: var(--text2); margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border); line-height: 1.6; }
.exp-what-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); margin-bottom: 4px; }
.exp-tools { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }
.tool-chip { font-size: 10px; font-weight: 600; padding: 3px 8px; border-radius: 4px; background: var(--surface2); border: 1px solid var(--border2); color: var(--text2); font-family: 'JetBrains Mono', monospace; }
.exp-steps-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); margin-bottom: 10px; }
.exp-step { display: flex; gap: 10px; margin-bottom: 8px; align-items: flex-start; }
.step-num { width: 20px; height: 20px; border-radius: 50%; background: var(--surface2); border: 1px solid var(--border2); color: var(--text3); font-size: 10px; font-weight: 700; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 1px; }
.step-body { flex: 1; }
.step-text { font-size: 12.5px; color: var(--text2); line-height: 1.5; }
.step-cmd { display: block; margin-top: 5px; background: var(--surface); border: 1px solid var(--border); border-radius: 5px; padding: 7px 10px; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: var(--lo); position: relative; }
.step-cmd::before { content: '$ '; color: var(--text3); }
.exp-impact { margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); }
.exp-impact-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: var(--text3); margin-bottom: 4px; }
.exp-impact-text { font-size: 12px; color: var(--text2); line-height: 1.6; }

/* Empty state */
.empty { text-align: center; padding: 60px 20px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); }
.empty-icon { font-size: 32px; margin-bottom: 12px; }
.empty-title { font-size: 15px; font-weight: 600; color: var(--lo); margin-bottom: 6px; }
.empty-desc { font-size: 13px; color: var(--text3); }

/* Footer */
.footer { margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
.footer-left { font-size: 11px; color: var(--text3); }
.footer-right { font-size: 11px; color: var(--text3); }

@media (max-width: 900px) {
  .sidebar { display: none; }
  .main { padding: 20px; }
  .stat-grid { grid-template-columns: repeat(3, 1fr); }
  .overview-row { grid-template-columns: 1fr; }
}
@media print {
  .sidebar, .toolbar { display: none; }
  .f-body { display: block !important; }
  .exp-body { display: block !important; }
}
</style>
</head>
<body>
<div class="layout">

<!-- Sidebar -->
<aside class="sidebar">
  <div class="sb-logo">
    <div class="sb-logo-mark">
      <div class="sb-logo-icon">⚡</div>
      <div>
        <div class="sb-logo-name">WebVulnScanner</div>
        <div class="sb-logo-sub">by Aditya Singh</div>
      </div>
    </div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Navigation</div>
    <a class="sb-item active" href="#summary">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><rect x="1" y="1" width="4" height="4" rx="1" fill="currentColor"/><rect x="7" y="1" width="4" height="4" rx="1" fill="currentColor"/><rect x="1" y="7" width="4" height="4" rx="1" fill="currentColor"/><rect x="7" y="7" width="4" height="4" rx="1" fill="currentColor"/></svg>
      Summary
    </a>
    <a class="sb-item" href="#findings">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="5" cy="5" r="4" stroke="currentColor" stroke-width="1.2"/><path d="M8.5 8.5L11 11" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
      All Findings
      {% if total_findings > 0 %}<span class="sb-count">{{ total_findings }}</span>{% endif %}
    </a>
  </div>
  {% if counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.INFO > 0 %}
  <div class="sb-section">
    <div class="sb-label">By Severity</div>
    {% if counts.CRITICAL > 0 %}<a class="sb-item" href="#sec-CRITICAL"><span class="sb-dot cr"></span> Critical <span class="sb-count cr">{{ counts.CRITICAL }}</span></a>{% endif %}
    {% if counts.HIGH > 0 %}<a class="sb-item" href="#sec-HIGH"><span class="sb-dot hi"></span> High <span class="sb-count hi">{{ counts.HIGH }}</span></a>{% endif %}
    {% if counts.MEDIUM > 0 %}<a class="sb-item" href="#sec-MEDIUM"><span class="sb-dot me"></span> Medium <span class="sb-count me">{{ counts.MEDIUM }}</span></a>{% endif %}
    {% if counts.LOW > 0 %}<a class="sb-item" href="#sec-LOW"><span class="sb-dot lo"></span> Low <span class="sb-count">{{ counts.LOW }}</span></a>{% endif %}
    {% if counts.INFO > 0 %}<a class="sb-item" href="#sec-INFO"><span class="sb-dot in"></span> Info <span class="sb-count">{{ counts.INFO }}</span></a>{% endif %}
  </div>
  {% endif %}
  <div class="sb-foot">
    <div class="sb-author">
      <div class="sb-avatar">AS</div>
      <div class="sb-author-info">
        <div class="sb-author-name">Aditya Singh</div>
        <div class="sb-author-role">Security Researcher</div>
      </div>
    </div>
    <div class="sb-links">
      <a class="sb-link-item" href="https://github.com/Adityasiig" target="_blank">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        github.com/Adityasiig
      </a>
      <a class="sb-link-item" href="https://adityasiig.github.io/Portfolio/" target="_blank">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        Portfolio
      </a>
      <a class="sb-link-item" href="https://adityasiig.github.io/terminal-portfolio/" target="_blank">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
        Terminal Portfolio
      </a>
    </div>
    <div class="sb-meta">
      {{ scan_date }}<br>
      {{ urls_crawled }} URLs · {{ duration }}s
    </div>
  </div>
</aside>

<!-- Main -->
<main class="main">

  <!-- Page header -->
  <div class="page-header" id="summary">
    <div class="page-eyebrow">Vulnerability Scan Report</div>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;">
      <div>
        <div class="page-title">{{ target }}</div>
        <div class="page-url">Scanned {{ scan_date }}</div>
      </div>
      <div class="risk-badge risk-{{ overall_risk }}">
        {{ overall_risk }} RISK
      </div>
    </div>
    <div class="page-meta">
      <div class="meta-item"><span class="meta-label">URLs</span><span class="meta-value">{{ urls_crawled }}</span></div>
      <div class="meta-item"><span class="meta-label">Forms</span><span class="meta-value">{{ forms_found }}</span></div>
      <div class="meta-item"><span class="meta-label">Findings</span><span class="meta-value">{{ total_findings }}</span></div>
      <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">{{ duration }}s</span></div>
      <div class="meta-item"><span class="meta-label">Modules</span><span class="meta-value">{{ module_summary | length }}</span></div>
    </div>
  </div>

  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card stat-cr"><div class="stat-num" data-target="{{ counts.CRITICAL }}">{{ counts.CRITICAL }}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card stat-hi"><div class="stat-num" data-target="{{ counts.HIGH }}">{{ counts.HIGH }}</div><div class="stat-label">High</div></div>
    <div class="stat-card stat-me"><div class="stat-num" data-target="{{ counts.MEDIUM }}">{{ counts.MEDIUM }}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card stat-lo"><div class="stat-num" data-target="{{ counts.LOW }}">{{ counts.LOW }}</div><div class="stat-label">Low</div></div>
    <div class="stat-card stat-in"><div class="stat-num" data-target="{{ counts.INFO }}">{{ counts.INFO }}</div><div class="stat-label">Info</div></div>
  </div>

  <!-- Overview -->
  {% set total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.INFO %}
  {% set tnz = total if total > 0 else 1 %}
  <div class="overview-row">
    <div class="ov-card">
      <div class="ov-title">Severity Breakdown</div>
      <div class="bar-row"><span class="bar-label" style="color:var(--cr)">Critical</span><div class="bar-track"><div class="bar-fill" style="background:var(--cr)" data-w="{{ (counts.CRITICAL/tnz*100)|int }}"></div></div><span class="bar-val">{{ counts.CRITICAL }}</span></div>
      <div class="bar-row"><span class="bar-label" style="color:var(--hi)">High</span><div class="bar-track"><div class="bar-fill" style="background:var(--hi)" data-w="{{ (counts.HIGH/tnz*100)|int }}"></div></div><span class="bar-val">{{ counts.HIGH }}</span></div>
      <div class="bar-row"><span class="bar-label" style="color:var(--me)">Medium</span><div class="bar-track"><div class="bar-fill" style="background:var(--me)" data-w="{{ (counts.MEDIUM/tnz*100)|int }}"></div></div><span class="bar-val">{{ counts.MEDIUM }}</span></div>
      <div class="bar-row"><span class="bar-label" style="color:var(--lo)">Low</span><div class="bar-track"><div class="bar-fill" style="background:var(--lo)" data-w="{{ (counts.LOW/tnz*100)|int }}"></div></div><span class="bar-val">{{ counts.LOW }}</span></div>
      <div class="bar-row"><span class="bar-label" style="color:var(--in)">Info</span><div class="bar-track"><div class="bar-fill" style="background:var(--in)" data-w="{{ (counts.INFO/tnz*100)|int }}"></div></div><span class="bar-val">{{ counts.INFO }}</span></div>
    </div>
    <div class="ov-card" style="display:flex;flex-direction:column;align-items:center;justify-content:center;">
      <div class="ov-title" style="text-align:center">Distribution</div>
      <div class="chart-wrap"><canvas id="sevChart" width="160" height="160"></canvas></div>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar" id="findings">
    <input type="text" class="search-input" id="srch" placeholder="Search findings..." oninput="doFilter()">
    <button class="filter-btn on" id="fb-ALL" onclick="setSev('ALL')">All ({{ total_findings }})</button>
    {% if counts.CRITICAL > 0 %}<button class="filter-btn" id="fb-CRITICAL" onclick="setSev('CRITICAL')">Critical</button>{% endif %}
    {% if counts.HIGH > 0 %}<button class="filter-btn" id="fb-HIGH" onclick="setSev('HIGH')">High</button>{% endif %}
    {% if counts.MEDIUM > 0 %}<button class="filter-btn" id="fb-MEDIUM" onclick="setSev('MEDIUM')">Medium</button>{% endif %}
    {% if counts.LOW > 0 %}<button class="filter-btn" id="fb-LOW" onclick="setSev('LOW')">Low</button>{% endif %}
    {% if counts.INFO > 0 %}<button class="filter-btn" id="fb-INFO" onclick="setSev('INFO')">Info</button>{% endif %}
    <div class="tb-sep"></div>
    <button class="tb-btn" onclick="expandAll()">Expand all</button>
    <button class="tb-btn" onclick="collapseAll()">Collapse all</button>
    <button class="tb-btn" onclick="window.print()">Print</button>
  </div>

  <!-- Findings -->
  {% if findings %}
    {% for severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] %}
    {% set sf = findings | selectattr("severity","equalto",severity) | list %}
    {% if sf %}
    <div class="sec-group" id="sec-{{ severity }}" data-sec="{{ severity }}">
      <div class="sec-header">
        <span class="sec-dot {{ severity | lower }}"></span>
        <span class="sec-title">{{ severity | title }} Severity</span>
        <span class="sec-count">{{ sf | length }} finding{{ 's' if sf|length != 1 else '' }}</span>
      </div>
      {% for f in sf %}
      <div class="f-card sev-{{ f.severity }}"
           data-sev="{{ f.severity }}"
           data-txt="{{ (f.type ~ ' ' ~ f.module ~ ' ' ~ (f.url or '') ~ ' ' ~ f.description) | lower }}">
        <button class="f-head" onclick="toggleCard(this.parentElement)">
          <span class="f-module">{{ f.module }}</span>
          <span class="f-title">{{ f.type }}</span>
          <span class="f-pill {{ f.severity }}">{{ f.severity }}</span>
          <span class="f-chevron">▼</span>
        </button>
        <div class="f-body">
          <p class="f-desc">{{ f.description }}</p>
          <div class="f-grid">
            {% if f.url %}<div class="f-field full"><div class="f-field-label">URL</div><div class="f-field-value url-val">{{ f.url }}</div></div>{% endif %}
            {% if f.parameter %}<div class="f-field"><div class="f-field-label">Parameter</div><div class="f-field-value pm-val">{{ f.parameter }}</div></div>{% endif %}
            {% if f.evidence %}<div class="f-field {{ '' if f.parameter else 'full' }}"><div class="f-field-label">Evidence</div><div class="f-field-value ev-val">{{ f.evidence }}</div></div>{% endif %}
          </div>
          {% if f.payload %}
          <div class="payload-block">
            <div class="payload-label">Payload</div>
            <div class="payload-code" id="pl-{{ loop.index }}-{{ severity }}">{{ f.payload }}</div>
            <button class="copy-btn" data-target="pl-{{ loop.index }}-{{ severity }}" onclick="doCopy(this)">Copy</button>
          </div>
          {% endif %}
          {% if f.recommendation is defined and f.recommendation %}
          <div class="fix-box">
            <div class="fix-label">Recommended Fix</div>
            <div class="fix-value">{{ f.recommendation }}</div>
          </div>
          {% endif %}
          {% if f.exploitation is defined and f.exploitation and f.severity in ['CRITICAL','HIGH','MEDIUM'] %}
          <button class="exp-toggle" onclick="toggleExp(this)">
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M6 1v4M6 7v4M1 6h4M7 6h4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
            Exploitation Guide — Step by Step
            <span style="font-size:10px;color:var(--text3);font-weight:400;margin-left:4px">beginner friendly</span>
            <span class="exp-toggle-arrow">▼</span>
          </button>
          <div class="exp-body">
            <div class="exp-what-label">What is this?</div>
            <div class="exp-what">{{ f.description }}</div>
            {% set tool_map = {'sqlmap':'sqlmap','bettercap':'Bettercap','sslstrip':'sslstrip','mitmproxy':'mitmproxy','nmap':'nmap','metasploit':'Metasploit','wireshark':'Wireshark','burp':'Burp Suite','curl':'curl','hashcat':'hashcat','john':'John the Ripper','hydra':'Hydra','beef':'BeEF','openssl':'openssl','git-dumper':'git-dumper','testssl':'testssl.sh','ysoserial':'ysoserial','wpscan':'WPScan','nikto':'Nikto'} %}
            {% set exp_lower = f.exploitation | lower %}
            {% set tools_found = [] %}
            {% for key, label in tool_map.items() %}{% if key in exp_lower %}{% set _ = tools_found.append(label) %}{% endif %}{% endfor %}
            {% if tools_found %}
            <div style="margin-bottom:14px">
              <div class="exp-steps-label">Tools needed</div>
              <div class="exp-tools">{% for t in tools_found %}<span class="tool-chip">{{ t }}</span>{% endfor %}</div>
            </div>
            {% endif %}
            <div class="exp-steps-label">Steps</div>
            {% set steps = f.exploitation.split('\n') %}
            {% set ns = namespace(idx=0) %}
            {% for line in steps %}{% set stripped = line.strip() %}{% if stripped %}
            {% set ns.idx = ns.idx + 1 %}
            {% set clean = stripped | regex_replace('^\\d+\\.\\s*', '') %}
            {% set is_cmd = false %}
            {% for kw in ['sqlmap','bettercap','sslstrip','nmap','curl ','hashcat','john ','hydra','openssl','ssh ','wget ','msfconsole','python ','git-dumper','testssl','nc '] %}{% if kw in clean | lower %}{% set is_cmd = true %}{% endif %}{% endfor %}
            <div class="exp-step">
              <span class="step-num">{{ ns.idx }}</span>
              <div class="step-body">
                {% if is_cmd %}
                  {% if ': ' in clean and clean.index(': ') < 55 %}
                    <span class="step-text">{{ clean.split(': ')[0] }}:</span>
                    <code class="step-cmd">{{ clean.split(': ',1)[1] }}</code>
                  {% else %}
                    <code class="step-cmd">{{ clean }}</code>
                  {% endif %}
                {% else %}
                  <span class="step-text">{{ clean }}</span>
                {% endif %}
              </div>
            </div>
            {% endif %}{% endfor %}
            <div class="exp-impact">
              <div class="exp-impact-label">Potential impact</div>
              <div class="exp-impact-text">
                {% if f.severity == 'CRITICAL' %}Full compromise possible — data breach, remote code execution, or complete loss of control. Treat as an emergency and fix immediately.
                {% elif f.severity == 'HIGH' %}Significant risk — account takeover, sensitive data exposure, or major functionality abuse. Fix as soon as possible.
                {% elif f.severity == 'MEDIUM' %}Moderate risk — may be chained with other issues for greater impact. Should be addressed in your next release cycle.
                {% endif %}
              </div>
            </div>
          </div>
          {% endif %}
        </div>
      </div>
      {% endfor %}
    </div>
    {% endif %}
    {% endfor %}
  {% else %}
  <div class="empty">
    <div class="empty-icon">✓</div>
    <div class="empty-title">No vulnerabilities found</div>
    <div class="empty-desc">The target appears secure, or no crawlable attack surface was detected.</div>
  </div>
  {% endif %}

  <div class="footer">
    <span class="footer-left">
      Built by <a href="https://github.com/Adityasiig" target="_blank" style="color:var(--blue)">Aditya Singh</a>
      &nbsp;·&nbsp;
      <a href="https://github.com/Adityasiig/WebVulnScanner" target="_blank" style="color:var(--text3)">View on GitHub</a>
      &nbsp;·&nbsp;
      <span style="color:var(--text3)">For authorized testing only</span>
    </span>
    <span class="footer-right">{{ scan_date }}</span>
  </div>
</main>
</div>

<script>
// Card toggle
function toggleCard(card) { card.classList.toggle('open'); }
function expandAll() { document.querySelectorAll('.f-card:not(.hidden)').forEach(c => c.classList.add('open')); }
function collapseAll() { document.querySelectorAll('.f-card').forEach(c => c.classList.remove('open')); }

// Exploit toggle
function toggleExp(btn) {
  const body = btn.nextElementSibling;
  const open = body.style.display === 'block';
  body.style.display = open ? 'none' : 'block';
  btn.classList.toggle('open', !open);
}

// Filter
let curSev = 'ALL';
function setSev(sev) {
  curSev = sev;
  document.querySelectorAll('[id^="fb-"]').forEach(b => {
    b.className = 'filter-btn';
    if (b.id === 'fb-' + sev) {
      const cls = {'ALL':'on','CRITICAL':'on-cr','HIGH':'on-hi','MEDIUM':'on-me','LOW':'on-lo'};
      b.className = 'filter-btn ' + (cls[sev] || 'on');
    }
  });
  doFilter();
}
function doFilter() {
  const q = document.getElementById('srch').value.toLowerCase();
  document.querySelectorAll('.f-card').forEach(c => {
    const sevOk = curSev === 'ALL' || c.dataset.sev === curSev;
    const txtOk = !q || c.dataset.txt.includes(q);
    c.classList.toggle('hidden', !(sevOk && txtOk));
  });
  document.querySelectorAll('.sec-group').forEach(g => {
    const vis = g.querySelectorAll('.f-card:not(.hidden)').length > 0;
    g.style.display = (curSev !== 'ALL' && g.dataset.sec && g.dataset.sec !== curSev) ? 'none' : (vis ? '' : 'none');
  });
}

// Copy button
function doCopy(btn) {
  const el = document.getElementById(btn.dataset.target);
  navigator.clipboard.writeText(el.textContent).then(() => {
    btn.textContent = 'Copied'; btn.classList.add('ok');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 1500);
  });
}

// Animate stat counters
document.querySelectorAll('.stat-num[data-target]').forEach(el => {
  const target = parseInt(el.dataset.target);
  if (!target) return;
  let start = null;
  const dur = 600;
  function step(ts) {
    if (!start) start = ts;
    const p = Math.min((ts - start) / dur, 1);
    el.textContent = Math.floor(p * target);
    if (p < 1) requestAnimationFrame(step); else el.textContent = target;
  }
  requestAnimationFrame(step);
});

// Animate bars
setTimeout(() => {
  document.querySelectorAll('.bar-fill[data-w]').forEach(el => {
    el.style.width = el.dataset.w + '%';
  });
}, 100);

// Chart
const ctx = document.getElementById('sevChart');
if (ctx) {
  const data = [{{ counts.CRITICAL }}, {{ counts.HIGH }}, {{ counts.MEDIUM }}, {{ counts.LOW }}, {{ counts.INFO }}];
  const total = data.reduce((a,b) => a+b, 0);
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low','Info'],
      datasets: [{ data, backgroundColor: ['#e5534b','#e8813a','#c9a227','#3fb950','#484f58'], borderWidth: 0, hoverOffset: 4 }]
    },
    options: {
      cutout: '70%',
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw}${total ? ' (' + Math.round(ctx.raw/total*100) + '%)' : ''}`
          },
          backgroundColor: '#1c1c1c', borderColor: '#2a2a2a', borderWidth: 1,
          titleColor: '#e8e8e8', bodyColor: '#999', padding: 10, cornerRadius: 6
        }
      },
      animation: { animateRotate: true, duration: 700 }
    }
  });
}

// Sidebar active link on scroll
const sections = document.querySelectorAll('[id]');
window.addEventListener('scroll', () => {
  let cur = '';
  sections.forEach(s => { if (window.scrollY >= s.offsetTop - 80) cur = s.id; });
  document.querySelectorAll('.sb-item').forEach(a => {
    a.classList.toggle('active', a.getAttribute('href') === '#' + cur);
  });
}, { passive: true });
</script>
</body>
</html>"""


def generate_report(target, findings, crawl_data, duration, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = (target
              .replace("https://", "").replace("http://", "")
              .replace("/", "_").replace(":", "_"))

    # JSON report
    json_path = os.path.join(output_dir, f"scan_{domain}_{timestamp}.json")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "INFO"), 4))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    if counts["CRITICAL"] > 0:    overall_risk = "CRITICAL"
    elif counts["HIGH"] > 0:      overall_risk = "HIGH"
    elif counts["MEDIUM"] > 0:    overall_risk = "MEDIUM"
    elif counts["LOW"] > 0:       overall_risk = "LOW"
    elif counts["INFO"] > 0:      overall_risk = "LOW"
    else:                          overall_risk = "NONE"

    module_map = {}
    for f in findings:
        m = f.get("module", "Unknown")
        s = f.get("severity", "INFO")
        if m not in module_map:
            module_map[m] = {"count": 0, "highest": "INFO"}
        module_map[m]["count"] += 1
        if sev_rank.get(s, 0) > sev_rank.get(module_map[m]["highest"], 0):
            module_map[m]["highest"] = s
    module_summary = [{"module": k, "count": v["count"], "highest": v["highest"]} for k, v in module_map.items()]

    json_data = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "duration_seconds": round(duration, 2),
        "urls_crawled": len(crawl_data.get("urls", [])),
        "forms_found": len(crawl_data.get("forms", [])),
        "overall_risk": overall_risk,
        "summary": counts,
        "total_findings": len(findings),
        "findings": sorted_findings,
    }
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(json_data, jf, indent=2, ensure_ascii=False)
    print_info(f"JSON report: {json_path}")

    # HTML report
    html_path = os.path.join(output_dir, f"scan_{domain}_{timestamp}.html")
    env = Environment(autoescape=True)
    env.filters["regex_replace"] = lambda s, pattern, repl: re.sub(pattern, repl, s)
    template = env.from_string(HTML_TEMPLATE)
    html_content = template.render(
        target=target,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=round(duration, 2),
        urls_crawled=len(crawl_data.get("urls", [])),
        forms_found=len(crawl_data.get("forms", [])),
        counts=counts,
        findings=sorted_findings,
        overall_risk=overall_risk,
        module_summary=module_summary,
        total_findings=len(findings),
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print_info(f"HTML report: {html_path}")

    return json_path, html_path
