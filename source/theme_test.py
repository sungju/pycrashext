from rich.console import Console
from rich.markdown import Markdown
from pygments.styles import get_all_styles


with open(__file__) as f:
    res = f.read()

console = Console(color_system="truecolor")
# Checking code_theme options with result code
print(list(get_all_styles()))
for style in get_all_styles():
    console.print("=" * 60)
    console.print("Style: %s" % (style))
    console.print(Markdown("```python\n" + res + "```", code_theme=style))
