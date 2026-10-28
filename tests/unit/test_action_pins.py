from pathlib import Path

from tools.check_action_pins import main


def test_unpinned_action_reference_fails(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow.yml"
    workflow.write_text("- uses: actions/checkout@v4\n", encoding="utf-8")
    assert main(["check", str(workflow)]) == 1
