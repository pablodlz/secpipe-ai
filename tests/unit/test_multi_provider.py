"""Fallback do MultiProvider (FEAT-006): cai para o 1º que RESPONDE; todos falham -> levanta."""
from __future__ import annotations

import pytest

from secpipe.adapters.ai import MultiProvider, NoProviderAvailable, NullProvider


class _Fake:
    def __init__(self, name: str, *, up: bool, answer: str = "", boom: bool = False) -> None:
        self.name = name
        self._up = up
        self._answer = answer
        self._boom = boom

    def available(self) -> bool:
        return self._up

    def complete(self, prompt: str) -> str:
        if self._boom:
            raise RuntimeError("429 quota")
        return self._answer


def test_falls_through_to_first_that_responds() -> None:
    mp = MultiProvider([_Fake("a", up=True, boom=True), _Fake("b", up=True, answer="ok")])
    assert mp.complete("x") == "ok"


def test_skips_unavailable() -> None:
    mp = MultiProvider([_Fake("a", up=False), _Fake("b", up=True, answer="hi")])
    assert mp.complete("x") == "hi"


def test_all_failing_raises_with_causes() -> None:
    mp = MultiProvider([_Fake("a", up=True, boom=True), _Fake("b", up=True, boom=True)])
    with pytest.raises(NoProviderAvailable) as ei:
        mp.complete("x")
    assert "2" in str(ei.value)  # duas causas


def test_none_available_raises() -> None:
    mp = MultiProvider([NullProvider()])
    assert mp.available() is False
    with pytest.raises(NoProviderAvailable):
        mp.complete("x")
