"""The preview envelope and failure path never send data or echo input values."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from moonlight.cli import main
from moonlight.core.evidence import EvidenceKind
from moonlight.minimizer import MinimizationResult
from moonlight.minimizer.models import ModelPayload
from tests.test_minimizer import bundle


@pytest.mark.parametrize("shape", ["bundle", "array", "report"])
def test_cli_previews_exact_json_and_local_log(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    shape: str,
) -> None:
    source = bundle(
        [
            (EvidenceKind.USER, "decoy-host\\decoy-person"),
            (EvidenceKind.COMMAND_LINE, ["python.exe", "decoy-person", "x" * 1000]),
        ]
    )
    raw = source.model_dump(mode="json")
    data = (
        raw
        if shape == "bundle"
        else [raw]
        if shape == "array"
        else {
            "bundles": [raw],
            "file_contents": "CONTENT_MUST_STAY_LOCAL",
        }
    )
    input_file = tmp_path / "evidence.json"
    input_file.write_text(json.dumps(data), encoding="utf-8-sig")
    assert (
        main(["minimize", "--input", str(input_file), "--max-command-chars", "64"]) == 0
    )
    output = capsys.readouterr().out
    preview = MinimizationResult.model_validate_json(output)
    assert preview.redaction_log
    payload = ModelPayload.model_validate_json(preview.payload_bytes())
    assert payload.untrusted_evidence
    assert "decoy-person" not in output and "decoy-host" not in output
    assert "CONTENT_MUST_STAY_LOCAL" not in output
    assert len(list(tmp_path.iterdir())) == 1


def test_context_and_evidence_selection_apply_to_preview(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = bundle(
        [
            (EvidenceKind.COMMAND_LINE, ["EXPLICIT-DECOY"]),
            (EvidenceKind.IO_COUNTERS, {"write_bytes": 5}),
        ]
    )
    input_file, context_file = tmp_path / "input.json", tmp_path / "context.json"
    input_file.write_text(source.model_dump_json(), encoding="utf-8")
    context_file.write_text(
        '{"usernames":["explicit-decoy"],"hostnames":[]}', encoding="utf-8-sig"
    )
    assert (
        main(
            [
                "minimize",
                "--input",
                str(input_file),
                "--context",
                str(context_file),
                "--evidence-id",
                source.items[0].id,
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "explicit-decoy" not in output.casefold()
    assert "USER_1" in output
    assert source.items[1].id not in output


@pytest.mark.parametrize(
    "mode", ["invalid_json", "identity_collision", "unknown_id", "invalid_settings"]
)
def test_failures_produce_no_payload_and_do_not_echo_originals(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    source = bundle([(EvidenceKind.USER, "PRIVATE_ORIGINAL")])
    input_file = tmp_path / "input.json"
    input_file.write_text(
        source.model_dump_json() if mode != "invalid_json" else "PRIVATE_ORIGINAL",
        encoding="utf-8",
    )
    args = ["minimize", "--input", str(input_file)]
    if mode == "identity_collision":
        input_file.write_text(
            bundle([(EvidenceKind.USER, "value")]).model_dump_json(), encoding="utf-8"
        )
    if mode == "unknown_id":
        args += ["--evidence-id", "PRIVATE_ORIGINAL"]
    if mode == "invalid_settings":
        args += ["--max-command-chars", "0"]
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "PRIVATE_ORIGINAL" not in captured.err
    assert "retain local rules-only results" in captured.err
