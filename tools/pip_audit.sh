#!/bin/sh
set -eu
uv export --frozen --group dev --no-emit-project -o /tmp/requirements.txt
uv run pip-audit -r /tmp/requirements.txt
