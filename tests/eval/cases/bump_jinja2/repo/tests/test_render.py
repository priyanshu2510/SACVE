from app.render import render_greeting


def test_escapes_html():
    assert render_greeting("<b>x</b>") == "Hello &lt;b&gt;x&lt;/b&gt;!"
