"""``python -m model_wtf``: same entry point as the ``model-wtf`` script.

The MCP server is started by OpenCode through ``sys.executable -m model_wtf``
so that it runs in exactly the interpreter that has model-wtf installed,
without depending on a console script being on ``PATH``.
"""

from model_wtf.cli import cli

cli()
