"""Regenerate the checked-in process rule catalog."""

from __future__ import annotations

from pathlib import Path

from moonlight.rules.process import render_rule_docs


def main() -> None:
    path = Path(__file__).resolve().parents[3] / "docs" / "rules.md"
    path.write_text(render_rule_docs(), encoding="utf-8")


if __name__ == "__main__":
    main()
