"""score/v0: every vector in vectors/score/ through poaw_core.score_v0, and the CLI."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

SPEC = Path(__file__).parents[1]
sys.path.insert(0, str(Path(__file__).parents[2] / "core-python" / "src"))
import poaw_core as p  # noqa: E402

FILES = sorted((SPEC / "vectors" / "score").glob("*.json"))


def test_vectors_exist():
    assert len(FILES) >= 5


@pytest.mark.parametrize("path", FILES, ids=lambda f: f.name)
def test_score_vector(path):
    v = json.loads(path.read_text())
    assert p.score_v0(v["receipts"], v["as_of"]) == v["expected"], v["description"]


@pytest.mark.parametrize("path", FILES, ids=lambda f: f.name)
def test_cli_matches_vector(path, tmp_path):
    v = json.loads(path.read_text())
    f = tmp_path / "r.json"
    f.write_text(json.dumps(v["receipts"]))
    out = subprocess.run([sys.executable, str(SPEC / "tools" / "score.py"), "--as-of", v["as_of"], str(f)],
                         capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == v["expected"]
