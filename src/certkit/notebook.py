"""HTML rendering for notebooks, with the verdict discipline intact.

Jupyter calls ``_repr_html_()`` on whatever a cell evaluates to, so this is the
form most people will first see a result in. That makes it a place where a
verdict can quietly become something friendlier than the truth: a green tick, a
boolean, a "passed" badge. It does not, here.

Three colours for three verdicts, and ``UNVERIFIED`` gets its own -- neither the
green of an acceptance nor the red of a refusal, because it is neither. It is the
tool declining to answer, and a renderer that showed it as either would undo the
reason the third verdict exists.

The rendering imports nothing: no template engine, no CSS framework, no
JavaScript. It is `html.escape` and an f-string, so a hostile spec name cannot
inject markup into your notebook.
"""

from __future__ import annotations

from html import escape
from typing import Any

from .cert import ACCEPTED, REFUSED, UNVERIFIED

__all__ = ["report_html", "COLOURS"]

#: Border/background per verdict. UNVERIFIED is deliberately not a shade of
#: either of the others.
COLOURS: dict[str, tuple[str, str]] = {
    ACCEPTED: ("#0f7b3f", "#eaf6ee"),
    REFUSED: ("#a41b1b", "#fbeaea"),
    UNVERIFIED: ("#8a5a00", "#fff6e5"),
}

_MEANING = {
    ACCEPTED: "Every obligation was refuted, and the certificate is bound to this spec.",
    REFUSED: (
        "At least one obligation was not refuted. <b>This is not a proof that the "
        "guard is unsound</b> &mdash; only that this certificate does not establish it."
    ),
    UNVERIFIED: (
        "The arithmetic checked out, but a required precondition was never "
        "established, so <b>no claim is being made</b>. This is not a pass."
    ),
}


def report_html(report: Any, *, name: str = "") -> str:
    """Render a :class:`~certkit.cert.CheckReport` as standalone HTML.

    ``name`` is the spec name, shown escaped. Nothing here trusts its input:
    a spec called ``<script>`` renders as text.
    """
    verdict = report.verdict
    fg, bg = COLOURS.get(verdict, ("#333333", "#f2f2f2"))

    rows = []
    for o in report.obligations:
        mark = "ok" if o.get("ok") else "FAIL"
        reason = escape(str(o.get("reason") or ""))
        rows.append(
            f'<tr><td style="padding:2px 10px 2px 0">obligation {int(o.get("index", 0))}</td>'
            f'<td style="padding:2px 10px 2px 0"><code>{mark}</code></td>'
            f'<td style="padding:2px 0"><small>{reason}</small></td></tr>'
        )
    table = (
        f'<table style="border-collapse:collapse;margin-top:6px">{"".join(rows)}</table>'
        if rows
        else ""
    )

    title = escape(name) if name else "certificate"
    reason = escape(report.reason or "")
    reason_html = f'<div style="margin-top:6px"><small>{reason}</small></div>' if reason else ""

    return (
        f'<div style="border-left:4px solid {fg};background:{bg};padding:10px 14px;'
        f"font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;"
        f'color:#111;max-width:46em">'
        f'<div style="font-weight:700;color:{fg}">{escape(verdict)}</div>'
        f"<div>{title}</div>"
        f'<div style="margin-top:6px;font-family:system-ui,sans-serif">{_MEANING.get(verdict, "")}</div>'
        f"{table}{reason_html}"
        f"</div>"
    )
