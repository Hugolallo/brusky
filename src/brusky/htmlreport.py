"""Render a ScanResult as a single, self-contained HTML dashboard.

The output is one `.html` file with **no external dependencies** — all CSS and
JS are inlined — so it can be dropped anywhere and opened by double-clicking
(works over `file://`). It is meant to be produced at the end of a CLI run so a
human gets a clean, visual view of the whole scan without building a UI.

Design follows the repo's data-viz method: severity is a *status* palette
(critical/serious/warning), colors never carry meaning alone (every badge pairs
color with an icon + label), the headline numbers are a KPI row of stat tiles,
and the severity breakdown is a single part-to-whole stacked bar. Everything is
HTML-escaped at the boundary so advisory text can contain any characters.
"""

from __future__ import annotations

import html
import json

from brusky.model import Finding, ScanResult, Severity

# ── status palette (from the data-viz reference; icon+label always accompany) ──
# Severity is a status scale, not a categorical series. Each entry carries the
# fill, a text color that clears contrast on that fill, a glyph, and a label so
# color is never the sole signal.
_SEV_STYLE: dict[Severity, dict[str, str]] = {
    Severity.CRITICAL: {"fill": "#d03b3b", "ink": "#ffffff", "glyph": "⬤", "label": "Critical"},
    Severity.HIGH: {"fill": "#ec835a", "ink": "#3a1c0c", "glyph": "▲", "label": "High"},
    Severity.MEDIUM: {"fill": "#fab219", "ink": "#3a2c00", "glyph": "◆", "label": "Medium"},
    Severity.LOW: {"fill": "#7c8a9a", "ink": "#ffffff", "glyph": "▬", "label": "Low"},
    Severity.UNKNOWN: {"fill": "#b0b4ba", "ink": "#25272b", "glyph": "?", "label": "Unknown"},
}

_STATUS_LABEL = {"NEW": "New", "WORSENED": "Worsened", "EXISTING": "Existing"}

_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.UNKNOWN,
]


def to_html(result: ScanResult) -> str:
    """Return a complete, self-contained HTML document for `result`.

    Always renders the *full* set of findings (new + existing) — the HTML view
    is the whole picture — with new/worsened visually promoted and interactive
    filters layered on top.
    """
    ranked = result.ranked()
    counts = _counts(ranked)
    total = len(ranked)
    new_count = sum(1 for f in ranked if f.status in ("NEW", "WORSENED"))
    existing_count = sum(1 for f in ranked if f.status == "EXISTING")
    fixable = sum(1 for f in ranked if f.vuln.fixed_version)
    reachable = sum(1 for f in ranked if f.reachable is True)
    enriched = sum(1 for f in ranked if f.guidance)

    posture = _posture(counts, total)
    generated = result.timestamp or ""

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>Brusky report — {_esc(result.target)}</title>")
    parts.append(f"<style>{_CSS}</style>")
    parts.append("</head>")
    parts.append('<body class="viz-root">')

    # ── header ────────────────────────────────────────────────────────────
    parts.append('<header class="site-head">')
    parts.append('<div class="head-inner">')
    parts.append('<div class="brand"><span class="brand-mark">◈</span> Brusky</div>')
    parts.append(
        '<div class="head-meta">'
        f'<span class="head-target" title="scan target">{_esc(result.target)}</span>'
        f'<span class="head-time">{_esc(generated)}</span>'
        "</div>"
        '<button class="theme-toggle" type="button" aria-label="Toggle color theme">'
        '<span class="tt-dark">☾</span><span class="tt-light">☀</span></button>'
    )
    parts.append("</div>")
    parts.append("</header>")

    parts.append('<main class="wrap">')

    if result.errors:
        for err in result.errors:
            parts.append(f'<div class="banner banner-warn">⚠ {_esc(err)}</div>')

    # ── hero + posture ────────────────────────────────────────────────────
    parts.append('<section class="hero">')
    parts.append(
        f'<div class="hero-figure {posture["cls"]}">'
        f'<div class="hero-num">{total}</div>'
        f'<div class="hero-cap">vulnerable {_pluralize(total, "dependency", "dependencies")}</div>'
        "</div>"
    )
    parts.append(
        '<div class="hero-posture">'
        f'<div class="posture-pill {posture["cls"]}">{posture["glyph"]} {posture["label"]}</div>'
        f'<p class="posture-note">{_esc(posture["note"])}</p>'
        "</div>"
    )
    parts.append("</section>")

    # ── severity distribution (part-to-whole stacked bar) ─────────────────
    parts.append(_severity_bar(counts, total))

    # ── KPI row of stat tiles ─────────────────────────────────────────────
    parts.append('<section class="kpis" aria-label="Scan metrics">')
    parts.append(_tile(str(result.scanned_deps), "dependencies scanned", "neutral"))
    parts.append(_tile(str(new_count), "new / worsened", "accent" if new_count else "neutral"))
    parts.append(_tile(str(existing_count), "already known", "neutral"))
    parts.append(_tile(str(fixable), "have a fix available", "good" if fixable else "neutral"))
    if reachable:
        parts.append(_tile(str(reachable), "reachable in code", "warn"))
    if enriched:
        parts.append(_tile(str(enriched), "AI explainers", "neutral"))
    parts.append(
        _tile(str(len(result.ecosystems)), "ecosystems", "neutral",
              sub=", ".join(_esc(e) for e in result.ecosystems) or "—")
    )
    parts.append("</section>")

    # ── findings ──────────────────────────────────────────────────────────
    if not ranked:
        parts.append(
            '<section class="empty">'
            '<div class="empty-glyph">✓</div>'
            "<h2>No known vulnerabilities</h2>"
            "<p>Every scanned dependency came back clean against the advisory "
            "databases. Keep the daily scan running to catch new disclosures.</p>"
            "</section>"
        )
    else:
        parts.append(_filter_bar(counts, result.ecosystems))
        parts.append('<section class="findings" id="findings">')
        for f in ranked:
            parts.append(_finding_card(f))
        parts.append("</section>")
        parts.append(
            '<div class="no-match" id="no-match" hidden>'
            "No findings match the current filters.</div>"
        )

    parts.append("</main>")

    # ── footer ────────────────────────────────────────────────────────────
    parts.append(
        '<footer class="site-foot">'
        "<p>Generated by <strong>Brusky</strong> — a deterministic dependency "
        "security monitor. Vulnerability data from OSV.dev and endoflife.date. "
        "AI explainers (where shown) are advisory; verify before applying.</p>"
        "</footer>"
    )

    parts.append(f"<script>{_JS}</script>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


# ── section builders ──────────────────────────────────────────────────────────


def _severity_bar(counts: dict[Severity, int], total: int) -> str:
    if not total:
        return ""
    segs: list[str] = []
    legend: list[str] = []
    for sev in _SEV_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        st = _SEV_STYLE[sev]
        segs.append(
            f'<div class="bar-seg" style="--seg-fill:{st["fill"]};--seg-ink:{st["ink"]};'
            f'flex-grow:{n}" title="{n} {st["label"]}">'
            f'<span class="seg-label">{n}</span></div>'
        )
        legend.append(
            '<div class="legend-item">'
            f'<span class="legend-dot" style="background:{st["fill"]}">{st["glyph"]}</span>'
            f'<span class="legend-text">{st["label"]}</span>'
            f'<span class="legend-count">{n}</span>'
            "</div>"
        )
    return (
        '<section class="dist" aria-label="Severity distribution">'
        '<h2 class="section-h">Severity breakdown</h2>'
        f'<div class="bar" role="img" aria-label="Severity distribution bar">{"".join(segs)}</div>'
        f'<div class="legend">{"".join(legend)}</div>'
        "</section>"
    )


def _tile(value: str, label: str, tone: str, *, sub: str = "") -> str:
    sub_html = f'<div class="tile-sub">{sub}</div>' if sub else ""
    return (
        f'<div class="tile tile-{tone}">'
        f'<div class="tile-value">{_esc(value)}</div>'
        f'<div class="tile-label">{_esc(label)}</div>'
        f"{sub_html}"
        "</div>"
    )


def _filter_bar(counts: dict[Severity, int], ecosystems: list[str]) -> str:
    chips = ['<button class="chip chip-on" data-sev="all">All</button>']
    for sev in _SEV_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        st = _SEV_STYLE[sev]
        chips.append(
            f'<button class="chip" data-sev="{sev.name.lower()}">'
            f'<span class="chip-dot" style="background:{st["fill"]}"></span>'
            f'{st["label"]} <span class="chip-n">{n}</span></button>'
        )
    eco_opts = "".join(f'<option value="{_esc(e)}">{_esc(e)}</option>' for e in ecosystems)
    eco_select = (
        '<select class="filter-select" id="eco-filter" aria-label="Filter by ecosystem">'
        '<option value="all">All ecosystems</option>'
        f"{eco_opts}</select>"
        if len(ecosystems) > 1
        else ""
    )
    return (
        '<section class="filters" aria-label="Filters">'
        f'<div class="chip-row">{"".join(chips)}</div>'
        '<div class="filter-right">'
        '<label class="switch"><input type="checkbox" id="new-only">'
        '<span>New &amp; worsened only</span></label>'
        f"{eco_select}"
        '<input type="search" class="filter-search" id="search" '
        'placeholder="Search package or CVE…" aria-label="Search findings">'
        "</div>"
        "</section>"
    )


def _finding_card(f: Finding) -> str:
    st = _SEV_STYLE.get(f.severity, _SEV_STYLE[Severity.UNKNOWN])
    status = f.status if f.status in _STATUS_LABEL else "EXISTING"
    is_new = status in ("NEW", "WORSENED")

    tags: list[str] = []
    if f.dep.direct:
        tags.append('<span class="tag tag-direct">direct</span>')
    else:
        tags.append('<span class="tag">transitive</span>')
    if f.dep.dev:
        tags.append('<span class="tag">dev</span>')
    if f.reachable is True:
        tags.append('<span class="tag tag-reach">reachable</span>')
    elif f.reachable is False:
        tags.append('<span class="tag tag-quiet">not reachable</span>')

    fix = f.vuln.fixed_version
    if fix:
        fix_html = (
            '<div class="ver-flow"><span class="ver ver-bad">'
            f'{_esc(f.dep.version)}</span>'
            '<span class="ver-arrow">→</span>'
            f'<span class="ver ver-good">{_esc(fix)}</span></div>'
        )
    else:
        fix_html = (
            f'<div class="ver-flow"><span class="ver ver-bad">{_esc(f.dep.version)}</span>'
            '<span class="ver-none">no fix yet</span></div>'
        )

    cvss = ""
    if f.vuln.cvss_score is not None:
        cvss = (
            '<span class="cvss" title="CVSS score">'
            f"CVSS {_esc(_fmt_score(f.vuln.cvss_score))}</span>"
        )

    status_cls = "st-new" if is_new else "st-existing"
    status_pill = (
        f'<span class="status-pill {status_cls}">{_esc(_STATUS_LABEL[status])}</span>'
    )

    aliases = ""
    if f.vuln.aliases:
        aliases = (
            '<span class="aliases">'
            + " · ".join(_esc(a) for a in f.vuln.aliases)
            + "</span>"
        )

    search_blob = _esc(
        " ".join(
            [f.dep.name, f.vuln.id, f.vuln.summary, *f.vuln.aliases]
        ).lower()
    )

    body = [
        f'<article class="finding {"is-new" if is_new else ""}"'
        f' data-sev="{f.severity.name.lower()}" data-status="{"new" if is_new else "existing"}"'
        f' data-eco="{_esc(f.dep.ecosystem)}" data-text="{search_blob}">',
        '<div class="fc-accent" style="background:' + st["fill"] + '"></div>',
        '<div class="fc-main">',
        '<div class="fc-top">',
        f'<span class="sev-pill" style="--sev-fill:{st["fill"]};--sev-ink:{st["ink"]}">'
        f'<span class="sev-glyph">{st["glyph"]}</span>{st["label"]}</span>',
        f'<span class="pkg-name">{_esc(f.dep.name)}</span>',
        f'<span class="eco-badge">{_esc(f.dep.ecosystem)}</span>',
        status_pill,
        cvss,
        '<span class="fc-tags">' + "".join(tags) + "</span>",
        "</div>",
        '<div class="fc-mid">',
        fix_html,
        "</div>",
        '<div class="fc-vuln">',
        f'<a class="vuln-id" href="{_esc(f.vuln.advisory_url)}" target="_blank" '
        f'rel="noopener noreferrer">{_esc(f.vuln.id)} ↗</a>',
        aliases,
        f'<p class="vuln-sum">{_esc(f.vuln.summary) or "No summary provided."}</p>',
        "</div>",
    ]

    if f.guidance:
        body.append(_guidance_block(f))

    body.append("</div>")  # fc-main
    body.append("</article>")
    return "".join(body)


def _guidance_block(f: Finding) -> str:
    g = f.guidance
    assert g is not None
    conf = (g.confidence or "unrated").lower()
    rows: list[str] = []

    def field(title: str, value: str) -> None:
        if value:
            rows.append(
                f'<div class="g-field"><div class="g-field-h">{_esc(title)}</div>'
                f'<div class="g-field-b">{_esc(value)}</div></div>'
            )

    field("Why it's vulnerable", g.why_vulnerable)
    field("Impact", g.impact)
    field("Severity rationale", g.severity_rationale)
    if g.upgrade_summary or g.effort:
        eff = f' <span class="g-effort">{_esc(g.effort)} effort</span>' if g.effort else ""
        rows.append(
            f'<div class="g-field"><div class="g-field-h">Upgrade{eff}</div>'
            f'<div class="g-field-b">{_esc(g.upgrade_summary) or "—"}</div></div>'
        )

    if g.breaking_changes:
        items = "".join(f"<li>{_esc(b)}</li>" for b in g.breaking_changes)
        rows.append(
            '<div class="g-field"><div class="g-field-h">Breaking changes '
            '<span class="g-src-note">(from changelog)</span></div>'
            f'<ul class="g-list">{items}</ul></div>'
        )

    if g.code_touchpoints:
        items = "".join(
            '<li><code>'
            + _esc(str(t.get("file", "")))
            + (f":{_esc(str(t.get('line')))}" if t.get("line") is not None else "")
            + "</code>"
            + (f" — {_esc(str(t.get('note')))}" if t.get("note") else "")
            + "</li>"
            for t in g.code_touchpoints
        )
        rows.append(
            '<div class="g-field"><div class="g-field-h">Code to check in this repo</div>'
            f'<ul class="g-list g-code">{items}</ul></div>'
        )

    if g.sources:
        links = " ".join(
            f'<a href="{_esc(u)}" target="_blank" rel="noopener noreferrer">[{i + 1}]</a>'
            for i, u in enumerate(g.sources)
        )
        rows.append(
            f'<div class="g-field"><div class="g-field-h">Sources</div>'
            f'<div class="g-field-b g-sources">{links}</div></div>'
        )

    conf_cls = {"high": "conf-high", "medium": "conf-med", "low": "conf-low"}.get(
        conf, "conf-med"
    )
    return (
        '<details class="guidance">'
        '<summary class="g-summary">'
        '<span class="g-badge">✦ AI explainer &amp; upgrade guidance</span>'
        f'<span class="g-conf {conf_cls}">{_esc(conf)} confidence</span>'
        "</summary>"
        f'<div class="g-body">{"".join(rows)}</div>'
        '<div class="g-foot">Generated by '
        f'{_esc(g.model or "an LLM")} — verify before applying.</div>'
        "</details>"
    )


# ── small helpers ───────────────────────────────────────────────────────────


def _counts(findings: list[Finding]) -> dict[Severity, int]:
    out = {s: 0 for s in Severity}
    for f in findings:
        out[f.severity] += 1
    return out


def _posture(counts: dict[Severity, int], total: int) -> dict[str, str]:
    if total == 0:
        return {
            "cls": "p-clean",
            "glyph": "✓",
            "label": "Clean",
            "note": "No known vulnerabilities in scanned dependencies.",
        }
    if counts.get(Severity.CRITICAL):
        return {
            "cls": "p-critical",
            "glyph": "⬤",
            "label": "Critical exposure",
            "note": "Critical-severity vulnerabilities are present. Prioritize the "
            "flagged upgrades immediately.",
        }
    if counts.get(Severity.HIGH):
        return {
            "cls": "p-high",
            "glyph": "▲",
            "label": "High risk",
            "note": "High-severity vulnerabilities need prompt remediation.",
        }
    if counts.get(Severity.MEDIUM):
        return {
            "cls": "p-medium",
            "glyph": "◆",
            "label": "Moderate risk",
            "note": "Medium-severity issues to schedule into upcoming maintenance.",
        }
    return {
        "cls": "p-low",
        "glyph": "▬",
        "label": "Low risk",
        "note": "Only low or unrated findings — review at your convenience.",
    }


def _fmt_score(score: float) -> str:
    return f"{score:.1f}".rstrip("0").rstrip(".") if score % 1 else str(int(score))


def _pluralize(n: int, singular: str, plural: str) -> str:
    return singular if n == 1 else plural


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


# JSON-encode a value so it can be embedded in a <script> safely (used only if
# we later want to expose raw data; kept tiny + escaped for </script>).
def _js_json(value: object) -> str:
    return json.dumps(value).replace("</", "<\\/")


# ── inline assets ─────────────────────────────────────────────────────────────

_CSS = """
:root{
  --plane:#f9f9f7; --surface:#fcfcfb; --surface-2:#ffffff;
  --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --line:#c3c2b7; --border:rgba(11,11,11,.10);
  --accent:#2a78d6; --good:#0ca30c; --good-ink:#006300; --warn:#b8860b;
  --shadow:0 1px 2px rgba(11,11,11,.05),0 4px 16px rgba(11,11,11,.06);
  --radius:14px;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]){
    --plane:#0d0d0d; --surface:#1a1a19; --surface-2:#212120;
    --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --line:#383835; --border:rgba(255,255,255,.10);
    --accent:#3987e5; --good:#0ca30c; --good-ink:#0ca30c; --warn:#fab219;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 6px 24px rgba(0,0,0,.4);
  }
}
:root[data-theme=dark]{
  --plane:#0d0d0d; --surface:#1a1a19; --surface-2:#212120;
  --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --line:#383835; --border:rgba(255,255,255,.10);
  --accent:#3987e5; --good:#0ca30c; --good-ink:#0ca30c; --warn:#fab219;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 6px 24px rgba(0,0,0,.4);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--plane); color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
  font-size:15px; line-height:1.5; -webkit-font-smoothing:antialiased;
}
a{color:var(--accent)}
.wrap{max-width:1080px; margin:0 auto; padding:0 20px 64px}
.section-h{font-size:13px; letter-spacing:.04em; text-transform:uppercase;
  color:var(--muted); margin:0 0 12px; font-weight:600}

/* header */
.site-head{position:sticky; top:0; z-index:10; backdrop-filter:blur(8px);
  background:color-mix(in srgb,var(--plane) 88%,transparent);
  border-bottom:1px solid var(--border)}
.head-inner{max-width:1080px; margin:0 auto; padding:14px 20px; display:flex;
  align-items:center; gap:16px}
.brand{font-weight:700; font-size:17px; letter-spacing:-.01em; display:flex;
  align-items:center; gap:8px}
.brand-mark{color:var(--accent)}
.head-meta{margin-left:auto; text-align:right; display:flex; flex-direction:column;
  line-height:1.3; min-width:0}
.head-target{font-size:12.5px; color:var(--ink-2); font-variant-numeric:tabular-nums;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:52ch}
.head-time{font-size:11.5px; color:var(--muted); font-variant-numeric:tabular-nums}
.theme-toggle{border:1px solid var(--border); background:var(--surface); color:var(--ink);
  width:34px; height:34px; border-radius:9px; cursor:pointer; font-size:15px; flex:none}
.theme-toggle:hover{background:var(--surface-2)}
.tt-light{display:none}
:root[data-theme=dark] .tt-dark{display:none}
:root[data-theme=dark] .tt-light{display:inline}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]) .tt-dark{display:none}
  :root:not([data-theme=light]) .tt-light{display:inline}
}

/* banner */
.banner{margin:20px 0 0; padding:12px 16px; border-radius:10px; font-size:14px}
.banner-warn{background:color-mix(in srgb,#fab219 16%,var(--surface));
  border:1px solid color-mix(in srgb,#fab219 40%,var(--border)); color:var(--ink)}

/* hero */
.hero{display:flex; gap:28px; align-items:center; flex-wrap:wrap;
  margin:28px 0 24px; padding:24px; background:var(--surface);
  border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow)}
.hero-figure{text-align:center; min-width:150px; padding-right:28px;
  border-right:1px solid var(--border)}
.hero-num{font-size:64px; line-height:1; font-weight:700; letter-spacing:-.03em}
.hero-cap{font-size:12.5px; color:var(--muted); margin-top:6px; max-width:12ch;
  margin-left:auto; margin-right:auto}
.hero-figure.p-clean .hero-num{color:var(--good)}
.hero-figure.p-critical .hero-num{color:#d03b3b}
.hero-figure.p-high .hero-num{color:#ec835a}
.hero-figure.p-medium .hero-num{color:var(--warn)}
.hero-figure.p-low .hero-num{color:var(--ink-2)}
.hero-posture{flex:1; min-width:220px}
.posture-pill{display:inline-flex; align-items:center; gap:8px; font-weight:600;
  font-size:15px; padding:6px 14px; border-radius:999px}
.posture-pill.p-clean{color:var(--good-ink);
  background:color-mix(in srgb,var(--good) 16%,var(--surface))}
.posture-pill.p-critical{background:color-mix(in srgb,#d03b3b 16%,var(--surface)); color:#d03b3b}
.posture-pill.p-high{background:color-mix(in srgb,#ec835a 20%,var(--surface)); color:#b3541f}
.posture-pill.p-medium{background:color-mix(in srgb,#fab219 20%,var(--surface)); color:#8a6400}
.posture-pill.p-low{background:var(--surface-2); color:var(--ink-2)}
:root[data-theme=dark] .posture-pill.p-high{color:#ec835a}
:root[data-theme=dark] .posture-pill.p-medium{color:#fab219}
.posture-note{margin:12px 0 0; color:var(--ink-2); font-size:14.5px; max-width:52ch}

/* severity bar */
.dist{margin:24px 0}
.bar{display:flex; height:26px; border-radius:8px; overflow:hidden; gap:2px;
  background:var(--grid)}
.bar-seg{background:var(--seg-fill); min-width:26px; display:flex; align-items:center;
  justify-content:center}
.seg-label{color:var(--seg-ink); font-size:12px; font-weight:700;
  font-variant-numeric:tabular-nums}
.legend{display:flex; flex-wrap:wrap; gap:16px; margin-top:12px}
.legend-item{display:flex; align-items:center; gap:7px; font-size:13px}
.legend-dot{width:18px; height:18px; border-radius:5px; display:inline-flex;
  align-items:center; justify-content:center; color:#fff; font-size:10px;
  text-shadow:0 0 2px rgba(0,0,0,.3)}
.legend-text{color:var(--ink-2)}
.legend-count{font-weight:700; font-variant-numeric:tabular-nums}

/* KPI tiles */
.kpis{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:14px; margin:8px 0 28px}
.tile{background:var(--surface); border:1px solid var(--border); border-radius:12px;
  padding:16px 18px; box-shadow:var(--shadow); border-top:3px solid var(--line)}
.tile-value{font-size:30px; font-weight:700; letter-spacing:-.02em; line-height:1;
  font-variant-numeric:tabular-nums}
.tile-label{font-size:12.5px; color:var(--muted); margin-top:6px}
.tile-sub{font-size:12px; color:var(--ink-2); margin-top:4px}
.tile-accent{border-top-color:var(--accent)}
.tile-good{border-top-color:var(--good)}
.tile-warn{border-top-color:#fab219}

/* filters */
.filters{display:flex; flex-wrap:wrap; gap:14px; align-items:center;
  justify-content:space-between; margin:0 0 16px}
.chip-row{display:flex; flex-wrap:wrap; gap:8px}
.chip{display:inline-flex; align-items:center; gap:6px; border:1px solid var(--border);
  background:var(--surface); color:var(--ink-2); padding:6px 12px; border-radius:999px;
  font-size:13px; cursor:pointer; font-family:inherit}
.chip:hover{background:var(--surface-2)}
.chip-on{background:var(--ink); color:var(--plane); border-color:var(--ink)}
.chip-dot{width:9px; height:9px; border-radius:50%}
.chip-n{font-weight:700; font-variant-numeric:tabular-nums}
.filter-right{display:flex; gap:10px; align-items:center; flex-wrap:wrap}
.switch{display:inline-flex; align-items:center; gap:7px; font-size:13px; color:var(--ink-2);
  cursor:pointer; user-select:none}
.switch input{accent-color:var(--accent); width:15px; height:15px}
.filter-select,.filter-search{border:1px solid var(--border); background:var(--surface);
  color:var(--ink); padding:7px 11px; border-radius:9px; font-size:13px; font-family:inherit}
.filter-search{min-width:200px}
.filter-search:focus,.filter-select:focus{outline:2px solid var(--accent); outline-offset:1px}

/* findings */
.findings{display:flex; flex-direction:column; gap:12px}
.finding{display:flex; background:var(--surface); border:1px solid var(--border);
  border-radius:12px; overflow:hidden; box-shadow:var(--shadow)}
.finding.is-new{border-color:color-mix(in srgb,var(--accent) 45%,var(--border))}
.fc-accent{width:5px; flex:none}
.fc-main{padding:16px 18px; flex:1; min-width:0}
.fc-top{display:flex; flex-wrap:wrap; align-items:center; gap:9px}
.sev-pill{display:inline-flex; align-items:center; gap:5px; background:var(--sev-fill);
  color:var(--sev-ink); font-size:12px; font-weight:700; padding:3px 10px; border-radius:6px}
.sev-glyph{font-size:9px}
.pkg-name{font-weight:700; font-size:16px; letter-spacing:-.01em; word-break:break-word}
.eco-badge{font-size:11px; color:var(--muted); border:1px solid var(--border);
  padding:2px 7px; border-radius:5px}
.status-pill{font-size:11px; font-weight:600; padding:2px 9px; border-radius:999px}
.st-new{background:color-mix(in srgb,var(--accent) 18%,var(--surface)); color:var(--accent)}
.st-existing{background:var(--surface-2); color:var(--muted); border:1px solid var(--border)}
.cvss{font-size:11px; color:var(--ink-2); font-variant-numeric:tabular-nums;
  border:1px solid var(--border); padding:2px 7px; border-radius:5px}
.fc-tags{display:inline-flex; gap:6px; flex-wrap:wrap; margin-left:auto}
.tag{font-size:11px; color:var(--muted); background:var(--surface-2);
  border:1px solid var(--border); padding:2px 8px; border-radius:5px}
.tag-direct{color:var(--ink-2)}
.tag-reach{color:#b3541f; border-color:color-mix(in srgb,#ec835a 40%,var(--border))}
:root[data-theme=dark] .tag-reach{color:#ec835a}
.fc-mid{margin:12px 0 10px}
.ver-flow{display:inline-flex; align-items:center; gap:10px; font-size:14px;
  font-variant-numeric:tabular-nums}
.ver{padding:3px 9px; border-radius:6px; font-weight:600}
.ver-bad{background:color-mix(in srgb,#d03b3b 14%,var(--surface)); color:#d03b3b}
.ver-good{background:color-mix(in srgb,var(--good) 16%,var(--surface)); color:var(--good-ink)}
.ver-arrow{color:var(--muted)}
.ver-none{color:var(--muted); font-size:12.5px; font-style:italic}
.fc-vuln{border-top:1px solid var(--border); padding-top:11px}
.vuln-id{font-weight:600; font-size:13.5px; text-decoration:none}
.vuln-id:hover{text-decoration:underline}
.aliases{font-size:12px; color:var(--muted); margin-left:10px}
.vuln-sum{margin:6px 0 0; color:var(--ink-2); font-size:14px}

/* guidance */
.guidance{margin-top:12px; border:1px solid var(--border); border-radius:10px;
  background:var(--surface-2)}
.g-summary{list-style:none; cursor:pointer; padding:11px 14px; display:flex;
  align-items:center; gap:10px; flex-wrap:wrap; font-size:13px}
.g-summary::-webkit-details-marker{display:none}
.g-summary::before{content:"▸"; color:var(--muted); transition:transform .15s}
.guidance[open] .g-summary::before{transform:rotate(90deg)}
.g-badge{font-weight:600; color:var(--accent)}
.g-conf{margin-left:auto; font-size:11px; font-weight:600; padding:2px 9px; border-radius:999px}
.conf-high{background:color-mix(in srgb,var(--good) 16%,var(--surface)); color:var(--good-ink)}
.conf-med{background:color-mix(in srgb,#fab219 20%,var(--surface)); color:#8a6400}
.conf-low{background:color-mix(in srgb,#d03b3b 14%,var(--surface)); color:#d03b3b}
:root[data-theme=dark] .conf-med{color:#fab219}
.g-body{padding:2px 14px 6px; display:grid; gap:14px}
.g-field-h{font-size:11.5px; text-transform:uppercase; letter-spacing:.03em;
  color:var(--muted); font-weight:600; margin-bottom:3px}
.g-field-b{font-size:14px; color:var(--ink-2)}
.g-effort{text-transform:none; letter-spacing:0; color:var(--accent); font-weight:600}
.g-src-note{text-transform:none; letter-spacing:0; color:var(--muted); font-weight:400}
.g-list{margin:4px 0 0; padding-left:20px; font-size:14px; color:var(--ink-2)}
.g-list li{margin:2px 0}
.g-code code{background:var(--surface); border:1px solid var(--border); border-radius:4px;
  padding:1px 5px; font-size:12.5px}
.g-sources a{margin-right:8px; font-weight:600; text-decoration:none}
.g-foot{padding:9px 14px; border-top:1px solid var(--border); font-size:11.5px;
  color:var(--muted)}

/* empty + no-match */
.empty{text-align:center; padding:56px 20px; background:var(--surface);
  border:1px solid var(--border); border-radius:var(--radius);
  box-shadow:var(--shadow); margin-top:8px}
.empty-glyph{font-size:44px; color:var(--good); line-height:1}
.empty h2{margin:14px 0 6px; font-size:20px}
.empty p{color:var(--ink-2); max-width:46ch; margin:0 auto}
.no-match{text-align:center; padding:32px; color:var(--muted); font-size:14px}

/* footer */
.site-foot{border-top:1px solid var(--border); padding:24px 20px; margin-top:8px}
.site-foot p{max-width:1080px; margin:0 auto; color:var(--muted); font-size:12.5px}

@media (max-width:640px){
  .hero-figure{border-right:none; border-bottom:1px solid var(--border);
    padding-right:0; padding-bottom:18px; width:100%; min-width:0}
  .fc-tags{margin-left:0; width:100%}
}
@media print{
  .site-head,.filters,.theme-toggle{display:none}
  .finding,.tile,.hero{box-shadow:none; break-inside:avoid}
  .guidance[open]{break-inside:auto}
}
"""

_JS = """
(function(){
  "use strict";
  var root = document.documentElement;
  // theme toggle: respect OS default, allow explicit override
  var toggle = document.querySelector(".theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function(){
      var explicit = root.getAttribute("data-theme");
      var prefersDark = window.matchMedia &&
        window.matchMedia("(prefers-color-scheme: dark)").matches;
      var isDark = explicit ? explicit === "dark" : prefersDark;
      root.setAttribute("data-theme", isDark ? "light" : "dark");
    });
  }

  var cards = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  if (!cards.length) return;

  var sevFilter = "all";
  var newOnly = false;
  var ecoFilter = "all";
  var query = "";

  function apply(){
    var shown = 0;
    cards.forEach(function(c){
      var okSev = sevFilter === "all" || c.getAttribute("data-sev") === sevFilter;
      var okNew = !newOnly || c.getAttribute("data-status") === "new";
      var okEco = ecoFilter === "all" || c.getAttribute("data-eco") === ecoFilter;
      var okText = !query || (c.getAttribute("data-text") || "").indexOf(query) !== -1;
      var show = okSev && okNew && okEco && okText;
      c.hidden = !show;
      if (show) shown++;
    });
    var none = document.getElementById("no-match");
    if (none) none.hidden = shown !== 0;
  }

  var chips = document.querySelectorAll(".chip");
  chips.forEach(function(chip){
    chip.addEventListener("click", function(){
      chips.forEach(function(x){ x.classList.remove("chip-on"); });
      chip.classList.add("chip-on");
      sevFilter = chip.getAttribute("data-sev");
      apply();
    });
  });

  var newToggle = document.getElementById("new-only");
  if (newToggle) newToggle.addEventListener("change", function(){
    newOnly = newToggle.checked; apply();
  });

  var eco = document.getElementById("eco-filter");
  if (eco) eco.addEventListener("change", function(){
    ecoFilter = eco.value; apply();
  });

  var search = document.getElementById("search");
  if (search) search.addEventListener("input", function(){
    query = search.value.trim().toLowerCase(); apply();
  });
})();
"""
