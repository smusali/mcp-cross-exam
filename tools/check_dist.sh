#!/bin/sh
set -eu
uv build
uv run twine check --strict dist/*
uv run python tools/check_wheel.py
uv venv --python 3.13 /tmp/wheel-venv
uv pip install --python /tmp/wheel-venv/bin/python dist/*.whl
/tmp/wheel-venv/bin/mcp-cross-exam --help
/tmp/wheel-venv/bin/python -m mcp_cross_exam --help
