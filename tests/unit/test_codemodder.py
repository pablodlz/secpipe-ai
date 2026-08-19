"""Parser do relatório codetf do Codemodder (schema real). O run real é no container Linux."""
from __future__ import annotations

import json

from secpipe.adapters.codemodder import parse_codetf

_CODETF = json.dumps({
    "run": {"vendor": "pixee", "tool": "codemodder", "version": "6.5.5"},
    "results": [
        {
            "codemod": "pixee:python/harden-pyyaml",
            "changeset": [
                {"path": "app.py", "diff": "-x\n+y",
                 "changes": [{"lineNumber": 3, "description": "add Loader"}]}
            ],
        },
        {"codemod": "pixee:python/secure-random", "changeset": []},  # nada aplicado
    ],
})


def test_parse_counts_changes_and_codemods() -> None:
    out = parse_codetf(_CODETF)
    assert out.ran is True
    assert out.files_changed == 1
    assert out.changes == 1
    assert "pixee:python/harden-pyyaml" in out.codemods
    assert "pixee:python/secure-random" not in out.codemods   # changeset vazio nao conta


def test_empty_report_is_no_changes() -> None:
    out = parse_codetf("")
    assert out.ran is True and out.changes == 0
