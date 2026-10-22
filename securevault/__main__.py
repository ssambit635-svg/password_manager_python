"""
Allows `python -m securevault` to work exactly like running the script.

This is here because some people prefer the module form and some tools
(and test runners) expect a __main__.py to exist.
"""

import sys

from .cli import main


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
