from jinja2 import Environment, select_autoescape

_env = Environment(autoescape=select_autoescape(default=True))


def render_greeting(name: str) -> str:
    return _env.from_string("Hello {{ name }}!").render(name=name)
