"""A tiny SVG diagram builder for the hand-over document.

Colors come from CSS classes (``.dg-*`` in handover_assets.py) which use the page's theme tokens, so every diagram follows
light/dark mode. The builder checks that text fits its box and that nothing leaves the canvas, so a layout mistake fails the
build instead of shipping a clipped diagram.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field

CHAR_PX = {"dg-t": 7.1, "dg-s": 5.5, "dg-tag": 5.1, "dg-lbl": 5.6, "dg-h": 6.6}  # average glyph width per text class (IBM Plex Sans)
LINE_HEIGHT = 13.5


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def wrap(text: str, width_px: float, cls: str) -> list[str]:
    """Greedy word wrap by estimated glyph width."""
    limit = max(1, int(width_px / CHAR_PX[cls]))
    lines: list[str] = []
    current = ""
    for word in text.split():
        trial = f"{current} {word}".strip()
        if len(trial) <= limit or not current:
            current = trial
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


@dataclass
class Svg:
    """One diagram. Add boxes, groups and arrows, then call :meth:`render`."""

    width: int
    height: int
    title: str
    desc: str
    uid: str
    min_width: int = 720
    _parts: list[str] = field(default_factory=list)
    _kinds_used: set[str] = field(default_factory=set)

    # ---------------------------------------------------------------- bounds
    def _inside(self, x: float, y: float, w: float = 0, h: float = 0, what: str = "") -> None:
        if x < -0.5 or y < -0.5 or x + w > self.width + 0.5 or y + h > self.height + 0.5:
            raise ValueError(f"[{self.uid}] {what or 'element'} at ({x:.0f},{y:.0f},{w:.0f}x{h:.0f}) leaves the {self.width}x{self.height} canvas")

    # ---------------------------------------------------------------- primitives
    def group(self, x: float, y: float, w: float, h: float, label: str = "", kind: str = "") -> None:
        """A background container with an optional small-caps label."""
        self._inside(x, y, w, h, f"group {label!r}")
        self._parts.append(f'<rect class="dg-group {kind}" x="{x}" y="{y}" width="{w}" height="{h}" rx="9"/>')
        if label:
            self._parts.append(f'<text class="dg-h" x="{x + 12}" y="{y + 19}">{esc(label)}</text>')

    def box(self, x: float, y: float, w: float, h: float, title: str, sub: str = "", kind: str = "", tag: str = "", mono: bool = False) -> None:
        """A node: bold title, wrapped subtitle, optional red exit tag. Raises if the text does not fit."""
        self._inside(x, y, w, h, f"box {title!r}")
        title_lines = wrap(title, w - 20, "dg-t")
        sub_lines = wrap(sub, w - 20, "dg-s") if sub else []
        tag_lines = wrap(tag, w - 20, "dg-tag") if tag else []
        needed = 10 + 15 * len(title_lines) + (4 + LINE_HEIGHT * len(sub_lines) if sub_lines else 0) + (3 + 12 * len(tag_lines) if tag_lines else 0) + 6
        if needed > h + 0.5:
            raise ValueError(f"[{self.uid}] box {title!r} needs {needed:.0f}px of height but has {h:.0f}px")
        parts = [f'<rect class="dg-box {kind}" x="{x}" y="{y}" width="{w}" height="{h}" rx="7"/>']
        cy = y + 10 + 11
        for line in title_lines:
            parts.append(f'<text class="dg-t{" dg-mono" if mono else ""}" x="{x + 10}" y="{cy}">{esc(line)}</text>')
            cy += 15
        for line in sub_lines:
            parts.append(f'<text class="dg-s" x="{x + 10}" y="{cy}">{esc(line)}</text>')
            cy += LINE_HEIGHT
        ty = y + h - 7 - 12 * (len(tag_lines) - 1)
        for line in tag_lines:
            parts.append(f'<text class="dg-tag" x="{x + 10}" y="{ty}">{esc(line)}</text>')
            ty += 12
        self._parts.append("".join(parts))

    def badge(self, cx: float, cy: float, n: str) -> None:
        """A small numbered circle (use only for genuine sequences)."""
        self._inside(cx - 11, cy - 11, 22, 22, "badge")
        self._parts.append(f'<circle class="dg-badge" cx="{cx}" cy="{cy}" r="11"/><text class="dg-badge-t" x="{cx}" y="{cy + 4}" text-anchor="middle">{esc(n)}</text>')

    def text(self, x: float, y: float, s: str, cls: str = "dg-s", anchor: str = "start", max_width: float | None = None) -> None:
        """Free text, optionally wrapped to ``max_width`` (lines go downward)."""
        lines = wrap(s, max_width, cls) if max_width else [s]
        for i, line in enumerate(lines):
            est = len(line) * CHAR_PX[cls]
            left = x if anchor == "start" else x - est / 2 if anchor == "middle" else x - est
            self._inside(left, y - 10 + i * LINE_HEIGHT, est, 12, f"text {line[:24]!r}")
            self._parts.append(f'<text class="{cls}" x="{x}" y="{y + i * LINE_HEIGHT}" text-anchor="{anchor}">{esc(line)}</text>')

    def arrow(self, pts: list[tuple[float, float]], label: str = "", at: tuple[float, float] | None = None, kind: str = "", both: bool = False, head: bool = True, anchor: str = "middle") -> None:
        """A polyline arrow through ``pts``. ``kind``: '' | loop (red dashed) | soft (dashed) | good | block (red, no head)."""
        for px, py in pts:
            self._inside(px, py, 0, 0, "arrow point")
        self._kinds_used.add(kind)
        d = "M" + " L".join(f"{px} {py}" for px, py in pts)
        marker_end = f' marker-end="url(#{self.uid}-h-{kind or "n"})"' if head else ""
        marker_start = f' marker-start="url(#{self.uid}-h-{kind or "n"})"' if both else ""
        self._parts.append(f'<path class="dg-line {kind}" d="{d}"{marker_end}{marker_start}/>')
        if label:
            lx, ly = at if at else ((pts[0][0] + pts[-1][0]) / 2, (pts[0][1] + pts[-1][1]) / 2 - 6)
            est = len(label) * CHAR_PX["dg-lbl"]
            left = lx if anchor == "start" else lx - est / 2 if anchor == "middle" else lx - est
            self._inside(left, ly - 10, est, 13, f"label {label[:24]!r}")
            self._parts.append(f'<text class="dg-lbl" x="{lx}" y="{ly}" text-anchor="{anchor}">{esc(label)}</text>')

    def cross(self, cx: float, cy: float) -> None:
        """A red ✕ (something that is blocked)."""
        self._inside(cx - 8, cy - 8, 16, 16, "cross")
        self._parts.append(f'<path class="dg-cross" d="M{cx - 7} {cy - 7} L{cx + 7} {cy + 7} M{cx + 7} {cy - 7} L{cx - 7} {cy + 7}"/>')

    # ---------------------------------------------------------------- output
    def render(self) -> str:
        kinds = self._kinds_used | {""}
        markers = "".join(
            f'<marker id="{self.uid}-h-{k or "n"}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path class="dg-head {k}" d="M0 0 L10 5 L0 10 z"/></marker>'
            for k in sorted(kinds)
        )
        return (
            f'<svg class="dg" viewBox="0 0 {self.width} {self.height}" style="--dg-min:{self.min_width}px" role="img" aria-labelledby="{self.uid}-t {self.uid}-d" xmlns="http://www.w3.org/2000/svg">'
            f'<title id="{self.uid}-t">{esc(self.title)}</title><desc id="{self.uid}-d">{esc(self.desc)}</desc>'
            f"<defs>{markers}</defs>{''.join(self._parts)}</svg>"
        )


def figure(svg: Svg, caption: str, read: str = "") -> str:
    """Wrap a diagram with a caption and an optional how-to-read line."""
    how = f'<p class="how"><b>How to read it.</b> {read}</p>' if read else ""
    return f'<figure class="figure"><button class="zoombtn" type="button" aria-label="Enlarge diagram">Enlarge</button><div class="figscroll">{svg.render()}</div><figcaption>{caption}</figcaption>{how}</figure>'
