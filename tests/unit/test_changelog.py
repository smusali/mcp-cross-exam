from __future__ import annotations

import pytest
from tools.check_changelog import lint_text

_HEAD = "## [Unreleased]\n\n"


def _added(body: str) -> str:
    return _HEAD + "### Added\n\n" + body


@pytest.mark.parametrize(
    "text",
    [
        _added("- One sentence here. Another sentence follows.\n- Second entry stays valid.\n"),
        _added("- " + ("x" * 120) + ".\n- Second entry stays valid.\n"),
        _HEAD + "### Added\n\n- Only one entry in this section.\n",
    ],
)
def test_changelog_rule_failures(text: str) -> None:
    assert lint_text(text)
