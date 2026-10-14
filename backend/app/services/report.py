"""
One-page incident report (PDF) built from a recorded session trace.

Dependency-free on purpose: a single page of Helvetica text is a few dozen
lines of PDF. Only fields present in the trace are printed; anything not
measured is stated as unavailable. Text is Latin-1 only (other characters
become '?'), which is enough for an operator summary.
"""

from datetime import datetime, timezone

PAGE_W, PAGE_H = 595, 842
MARGIN = 48
WRAP = {"body": 100, "small": 112}      # characters per line at 9pt / 8pt (Helvetica, conservative)


def _wrap(text: str, width: int) -> list[str]:
    words, lines, line = text.split(), [], ""

    for word in words:
        while len(word) > width:                       # unbreakable token (hash, url)
            if line:
                lines.append(line)
                line = ""
            lines.append(word[:width])
            word = word[width:]

        if len(line) + len(word) + (1 if line else 0) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()

    if line:
        lines.append(line)

    return lines or [""]


def _esc(text: str) -> str:
    text = text.encode("latin-1", "replace").decode("latin-1")

    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _ts(iso: str) -> str:
    return iso[:19].replace("T", " ") + " UTC"


def _fmt(value, suffix="") -> str:
    return "unavailable" if value is None else f"{value}{suffix}"


def _lines(session: dict, stages: list[str], latency: dict) -> list[tuple[str, str, int, str]]:
    """(style, text, size, kind) rows: kind 'h' heading, 'b' body."""

    turns = session["turns"]
    demo = session["origin"] == "demo"
    flagged = [t for t in turns if t["route"] == "shadow"]
    categories = sorted({t["attack_category"] for t in turns if t["attack_category"] not in ("unknown", None)})
    order = ["UNKNOWN", "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity = max((t["severity"] for t in turns), key=lambda s: order.index(s) if s in order else 0)
    contained_at = flagged[0]["index"] if flagged else None
    incident = f"INC-{session['session_id'][-8:].upper()}"

    out = []

    def head(text):
        out.append(("B", text, 10, "h"))

    def body(text, size=9):
        out.append(("R", text, size, "b"))

    head("PROVENANCE")
    body("SIMULATED (scripted walkthrough, offline demo detector, not a live observation)" if demo
         else "LIVE traffic recorded by the running pipeline")

    head("INCIDENT")
    body(f"Incident ID: {incident}    Session ID: {session['session_id']}")
    body(f"Classification: {', '.join(categories) if categories else 'none observed'}    "
         f"Severity: {severity}    Status: {turns[-1]['status']}")
    body(f"Started: {_ts(session['started'])}    Last activity: {_ts(turns[-1]['ts'])}")

    head("SUMMARY OF OBSERVED ACTIVITY")
    body(f"{session['count']} messages; {len(flagged)} routed to the honeypot. "
         + (f"Containment began at message {contained_at}." if contained_at else "No containment occurred."))

    head("DETECTION OUTCOME")
    engines = sorted({t["model"] or t["engine"] for t in turns})
    body(f"Engine: {', '.join(engines)}. Highest risk score: {max(t['risk'] for t in turns):.2f}.")

    head("KILL-CHAIN EVENTS")
    seen = [t for t in turns if t["stage"]]
    if seen:
        for t in seen:
            body(f"#{t['index']} {_ts(t['ts'])}  {t['stage']}  ({t['attack_category']}, {t['severity']})", 8)
        body(f"Stages reached: {len(stages)} of {len(KILL_STAGES)} ({', '.join(stages) or 'none'}).", 8)
    else:
        body("No kill-chain stage was assigned to any message.", 8)

    head("LATENCY (recorded)")
    for key, label in (("sensors", "Fast path (sensors)"), ("agents", "Agent path"), ("total", "Total")):
        s = latency.get(key) or {}
        note = " [demo: no model call]" if demo and key == "agents" else ""
        body(f"{label}: avg {_fmt(s.get('avg'), ' ms')}, median {_fmt(s.get('median'), ' ms')}, "
             f"p95 {_fmt(s.get('p95'), ' ms')}, n={s.get('n', 0)}{note}", 8)

    head("ACTIONS TAKEN BY THE SYSTEM")
    if flagged:
        body(f"Session redirected to the honeypot from message {contained_at}; later messages stayed contained.", 8)
    else:
        body("None: the session was never contained.", 8)

    head("EVIDENCE REFERENCES")
    ids = [t["event_id"] for t in turns if t["event_id"]]
    body(f"Security event IDs: {', '.join(ids[:6])}" if ids
         else "No stored security events (demo sessions are not written to the event store)." if demo
         else "No security events were stored for this session.", 8)

    head("LIMITATIONS")
    body("Message text is redacted and truncated. " + (
        "Verdicts come from sensor rules, not the LLM agents. " if demo else "")
        + "Unavailable measurements are marked as such, never estimated.", 8)

    return out


KILL_STAGES = ["reconnaissance", "instruction_probing", "privilege_escalation", "data_discovery", "data_extraction"]


def build_pdf(session: dict, latency: dict) -> bytes:
    stages = session["turns"][-1]["completed_stages"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    demo = session["origin"] == "demo"

    ops = []
    y = PAGE_H - MARGIN

    def put(font, size, text, gap):
        nonlocal y
        ops.append(f"BT /{font} {size} Tf {MARGIN} {y:.1f} Td ({_esc(text)}) Tj ET")
        y -= gap

    title = "INCIDENT REPORT (SIMULATED)" if demo else "INCIDENT REPORT"
    put("B", 16, title, 20)
    put("R", 8, f"Generated {generated}   |   DEEP-DECEIVER", 16)
    ops.append(f"{MARGIN} {y + 8:.1f} m {PAGE_W - MARGIN} {y + 8:.1f} l S")
    y -= 6

    truncated = False

    for font, text, size, kind in _lines(session, stages, latency):
        rows = _wrap(text, WRAP["body"] if size >= 9 else WRAP["small"])
        gap = size + 3.5

        if kind == "h":
            y -= 5

        if y - gap * len(rows) < MARGIN + 14:
            truncated = True
            break

        for row in rows:
            put(font, size, row, gap)

    if truncated:
        put("R", 8, "(Truncated to one page. Use the JSON export for the full session.)", 10)

    stream = "\n".join(ops).encode("latin-1", "replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
        f"/Resources << /Font << /R 4 0 R /B 5 0 R >> >> /Contents 6 0 R >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []

    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"

    xref = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()

    for offset in offsets:
        pdf += f"{offset:010d} 00000 n \n".encode()

    pdf += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()

    return bytes(pdf)
