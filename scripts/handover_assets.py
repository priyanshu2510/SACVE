"""CSS and JavaScript of the hand-over document (kept apart from the content so each is easy to edit)."""

FONTS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap">'
)

CSS = """
/* Layout concept: a technical manual. A sticky contents rail on the left, one reading column on the right, dense but quiet tables.
   Boldness lives in one place: the status chips (done / partial / not started), the only saturated color on the page. */
:root {
  --bg: #f4f6f4;            /* paper, nudged toward the green of the ink */
  --surface: #ffffff;
  --surface-2: #eaeeeb;     /* table headers, code wells */
  --ink: #15201b;
  --muted: #55645c;
  --line: #d6ddd8;
  --accent: #1f5bb5;        /* links, active contents entry */
  --accent-soft: #e3ecf9;
  --done: #17703f;   --done-bg: #dcf1e5;
  --partial: #8a5200; --partial-bg: #fbecd0;
  --todo: #a8261d;   --todo-bg: #f9dedb;
  --info: #3a4f8a;   --info-bg: #e4e8f5;
  --code-ink: #1a2a22;
  --font-body: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0e1411; --surface: #151d19; --surface-2: #1d2823; --ink: #e4ebe7; --muted: #98a8a0; --line: #2a3832;
    --accent: #7eaaf2; --accent-soft: #1b2a45;
    --done: #62d494; --done-bg: #173625; --partial: #f0b45a; --partial-bg: #3a2a10; --todo: #ff8f86; --todo-bg: #402120;
    --info: #9fb2ee; --info-bg: #212a47; --code-ink: #d6e4dc; color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #0e1411; --surface: #151d19; --surface-2: #1d2823; --ink: #e4ebe7; --muted: #98a8a0; --line: #2a3832;
  --accent: #7eaaf2; --accent-soft: #1b2a45;
  --done: #62d494; --done-bg: #173625; --partial: #f0b45a; --partial-bg: #3a2a10; --todo: #ff8f86; --todo-bg: #402120;
  --info: #9fb2ee; --info-bg: #212a47; --code-ink: #d6e4dc; color-scheme: dark;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 1.25rem; }
body { background: var(--bg); color: var(--ink); font-family: var(--font-body); font-size: 15px; line-height: 1.6; }
a { color: var(--accent); text-underline-offset: 2px; }
a:focus-visible, button:focus-visible, input:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 3px; }

.shell { max-width: 1240px; margin: 0 auto; padding-inline: 16px; padding-block: 0 4rem; display: grid; grid-template-columns: 15.5rem minmax(0, 1fr); gap: 3rem; }
.rail { position: sticky; top: env(safe-area-inset-top, 0px); align-self: start; max-height: 100vh; overflow-y: auto; padding-block: 1.5rem; font-size: 13px; }
.rail .brand { font-weight: 600; font-size: 14px; letter-spacing: .01em; margin-bottom: .15rem; }
.rail .sub { color: var(--muted); font-size: 12px; margin-bottom: 1.1rem; }
.rail h2 { font-size: 10.5px; text-transform: uppercase; letter-spacing: .09em; color: var(--muted); font-weight: 600; margin: 1.1rem 0 .35rem; }
.rail a { display: block; padding: .18rem .5rem; margin-left: -.5rem; color: var(--ink); text-decoration: none; border-radius: 4px; }
.rail a:hover { background: var(--surface-2); }
.rail a.active { background: var(--accent-soft); color: var(--accent); font-weight: 500; }
.rail-mobile { display: none; }

main { min-width: 0; padding-top: 2rem; }
header.hero { padding-bottom: 1.75rem; border-bottom: 1px solid var(--line); margin-bottom: 2rem; }
.hero .kicker { font-family: var(--font-mono); font-size: 12px; color: var(--muted); letter-spacing: .02em; }
.hero h1 { font-size: clamp(1.9rem, 4vw, 2.7rem); line-height: 1.12; letter-spacing: -.02em; font-weight: 600; margin: .35rem 0 .75rem; text-wrap: balance; }
.hero p.lede { font-size: 1.08rem; max-width: 46rem; color: var(--ink); margin: 0 0 1.25rem; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr)); gap: .6rem; margin-top: 1.25rem; }
.stat { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: .6rem .8rem; }
.stat b { display: block; font-size: 1.35rem; font-weight: 600; font-variant-numeric: tabular-nums; letter-spacing: -.01em; }
.stat span { font-size: 12px; color: var(--muted); }

section { padding-block: 1.6rem .4rem; border-top: 1px solid var(--line); }
section:first-of-type { border-top: 0; padding-top: 0; }
h2 { font-size: 1.55rem; line-height: 1.2; letter-spacing: -.015em; font-weight: 600; margin: 0 0 .9rem; text-wrap: balance; }
h3 { font-size: 1.05rem; font-weight: 600; margin: 1.7rem 0 .5rem; letter-spacing: -.005em; }
h4 { font-size: .8rem; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); font-weight: 600; margin: 1.2rem 0 .3rem; }
p { margin: .55rem 0; max-width: 46rem; }
ul, ol { padding-left: 1.25rem; margin: .5rem 0; max-width: 46rem; }
li { margin: .25rem 0; }
li > p { margin: .2rem 0; }
code { font-family: var(--font-mono); font-size: .86em; background: var(--surface-2); padding: .08em .35em; border-radius: 3px; color: var(--code-ink); overflow-wrap: anywhere; }
pre { position: relative; font-family: var(--font-mono); font-size: 12.5px; line-height: 1.55; background: var(--surface-2); color: var(--code-ink); border: 1px solid var(--line); border-radius: 6px; padding: .8rem 1rem; overflow-x: auto; margin: .7rem 0; max-width: 100%; }
pre code { background: none; padding: 0; font-size: inherit; overflow-wrap: normal; }
.copy { position: absolute; top: .4rem; right: .4rem; font: 500 11px var(--font-body); background: var(--surface); color: var(--muted); border: 1px solid var(--line); border-radius: 4px; padding: .15rem .5rem; cursor: pointer; }
.copy:hover { color: var(--ink); }

.tablewrap { overflow-x: auto; margin: .8rem 0; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); max-width: 100%; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; vertical-align: top; padding: .5rem .75rem; border-bottom: 1px solid var(--line); }
th { background: var(--surface-2); font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); font-weight: 600; white-space: nowrap; }
tr:last-child td { border-bottom: 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td code { white-space: nowrap; }
td.wrap code { white-space: normal; }
.tablewrap.compact td, .tablewrap.compact th { padding: .32rem .6rem; font-size: 12.5px; }

.chip { display: inline-block; font-size: 11px; font-weight: 600; letter-spacing: .03em; padding: .1rem .5rem; border-radius: 99px; white-space: nowrap; vertical-align: 1px; }
.chip.done { color: var(--done); background: var(--done-bg); }
.chip.partial { color: var(--partial); background: var(--partial-bg); }
.chip.todo { color: var(--todo); background: var(--todo-bg); }
.chip.info { color: var(--info); background: var(--info-bg); }
.chip.p0 { color: var(--todo); background: var(--todo-bg); }
.chip.p1 { color: var(--partial); background: var(--partial-bg); }
.chip.p2 { color: var(--info); background: var(--info-bg); }
.size { font-family: var(--font-mono); font-size: 12px; color: var(--muted); }

.callout { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: .7rem .95rem; margin: .9rem 0; max-width: 46rem; }
.callout > b:first-child { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; margin-bottom: .2rem; color: var(--muted); }
.callout.warn { background: var(--partial-bg); border-color: transparent; }
.callout.warn > b:first-child { color: var(--partial); }
.callout.risk { background: var(--todo-bg); border-color: transparent; }
.callout.risk > b:first-child { color: var(--todo); }
.callout.ok { background: var(--done-bg); border-color: transparent; }
.callout.ok > b:first-child { color: var(--done); }
.callout p { margin: .25rem 0; }

.flow { display: flex; flex-wrap: wrap; align-items: center; gap: .35rem .3rem; margin: .8rem 0; font-family: var(--font-mono); font-size: 12px; }
.flow .n { background: var(--surface); border: 1px solid var(--line); border-radius: 5px; padding: .25rem .5rem; white-space: nowrap; }
.flow .n.io { background: var(--accent-soft); border-color: transparent; color: var(--accent); }
.flow .n.sb { border-style: dashed; }
.flow .ar { color: var(--muted); }
.flowkey { font-size: 12px; color: var(--muted); margin: -.3rem 0 .8rem; }

.layers { display: grid; gap: .6rem; margin: .9rem 0; }
.layer { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: .6rem .8rem; }
.layer > h5 { margin: 0 0 .4rem; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); font-weight: 600; }
.boxes { display: grid; grid-template-columns: repeat(auto-fit, minmax(10.5rem, 1fr)); gap: .45rem; }
.box { background: var(--surface-2); border-radius: 5px; padding: .4rem .6rem; font-size: 12.5px; min-width: 0; }
.box b { display: block; font-size: 12.5px; }
.box span { color: var(--muted); font-size: 11.5px; overflow-wrap: anywhere; }

.toolbar { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin: .6rem 0; }
input[type=search] { font: inherit; padding: .4rem .65rem; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); color: var(--ink); width: min(22rem, 100%); }
details { margin: .7rem 0; }
summary { cursor: pointer; font-weight: 500; padding: .2rem 0; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(17rem, 1fr)); gap: .75rem; margin: .8rem 0; }
.grid2 > div { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: .7rem .9rem; min-width: 0; }
.grid2 h4 { margin-top: 0; }
.grid2 ul { padding-left: 1.1rem; margin: .3rem 0 0; }
.muted { color: var(--muted); }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line); color: var(--muted); font-size: 12.5px; }
.tree { font-family: var(--font-mono); font-size: 12.5px; line-height: 1.7; }
.tree .d { font-weight: 500; }
.tree .c { color: var(--muted); font-family: var(--font-body); font-size: 12.5px; }

@media (max-width: 900px) {
  .shell { grid-template-columns: minmax(0, 1fr); gap: 0; }
  .rail { display: none; }
  .rail-mobile { display: block; position: sticky; top: env(safe-area-inset-top, 0px); z-index: 5; background: var(--bg); border-bottom: 1px solid var(--line); padding: .5rem 0; margin-inline: -16px; padding-inline: 16px; }
  .rail-mobile summary { font-weight: 600; }
  .rail-mobile nav { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: .1rem .8rem; padding-top: .5rem; max-height: 60vh; overflow-y: auto; }
  .rail-mobile a { color: var(--ink); text-decoration: none; padding: .25rem 0; font-size: 13.5px; }
  main { padding-top: 1.25rem; }
}
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
"""

JS = r"""
(function () {
  // Contents rail: highlight the section being read.
  var links = Array.prototype.slice.call(document.querySelectorAll('.rail a[href^="#"]'));
  var byId = {};
  links.forEach(function (a) { byId[a.getAttribute('href').slice(1)] = a; });
  var sections = Array.prototype.slice.call(document.querySelectorAll('main section[id]'));
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          links.forEach(function (a) { a.classList.remove('active'); });
          var a = byId[e.target.id]; if (a) a.classList.add('active');
        }
      });
    }, { rootMargin: '-10% 0px -80% 0px' });
    sections.forEach(function (s) { io.observe(s); });
  }
  // Mobile contents: close after choosing a section.
  document.querySelectorAll('.rail-mobile a').forEach(function (a) {
    a.addEventListener('click', function () { var d = a.closest('details'); if (d) d.open = false; });
  });
  // Copy buttons on code blocks.
  document.querySelectorAll('pre').forEach(function (pre) {
    var b = document.createElement('button'); b.className = 'copy'; b.type = 'button'; b.textContent = 'Copy';
    b.addEventListener('click', function () {
      var text = pre.innerText.replace(/\nCopy$/, '');
      function done() { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1400); }
      function fallback() { var r = document.createRange(); r.selectNodeContents(pre.querySelector('code') || pre); var s = getSelection(); s.removeAllRanges(); s.addRange(r); b.textContent = 'Selected'; }
      try { navigator.clipboard.writeText(text).then(done, fallback); } catch (e) { fallback(); }
    });
    pre.appendChild(b);
  });
  // Live filter for any table marked data-filterable (the settings catalogue).
  document.querySelectorAll('input[data-filter-for]').forEach(function (input) {
    var rows = Array.prototype.slice.call(document.querySelectorAll('#' + input.getAttribute('data-filter-for') + ' tbody tr'));
    var count = document.getElementById(input.getAttribute('data-filter-for') + '-count');
    input.addEventListener('input', function () {
      var q = input.value.trim().toLowerCase(), shown = 0;
      rows.forEach(function (r) {
        var hit = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        r.hidden = !hit; if (hit) shown++;
      });
      if (count) count.textContent = shown + ' of ' + rows.length + ' shown';
    });
  });
})();
"""
