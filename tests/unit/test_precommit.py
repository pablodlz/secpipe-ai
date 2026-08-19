"""O detector de supressão do `secpipe hook` (puro, sobre um diff)."""
from __future__ import annotations

from secpipe.application.use_cases.precommit import find_suppressions

_DIRTY = "+++ b/app.py\n+x = 1  # nosec B101\n+y = 2\n"
_CLEAN = "+++ b/app.py\n+x = 1\n+y = 2\n"


def test_flags_added_suppression() -> None:
    out = find_suppressions(_DIRTY)
    assert len(out) == 1
    assert "app.py" in out[0]


def test_clean_diff_is_empty() -> None:
    assert find_suppressions(_CLEAN) == []
