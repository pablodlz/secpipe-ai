"""Policy-as-code: regras ELEVAM o bloqueio (nunca relaxam). Match por cwe/tool/path/severidade."""
from __future__ import annotations

from secpipe.domain import Finding, GatePolicy, Report, ScanResult, ScanStatus, Severity
from secpipe.domain.rules import PolicyRule, blocked_by_rules
from secpipe.foundation.config import Config


def _f(cwe="CWE-89", tool="bandit", file="src/a.py", sev=Severity.MEDIUM) -> Finding:
    return Finding(tool, "r", sev, "m", file, 1, cwe=cwe)


def test_rule_matches_cwe() -> None:
    assert PolicyRule(cwe="CWE-89").matches(_f()) is True
    assert PolicyRule(cwe="CWE-79").matches(_f()) is False


def test_rule_matches_path_glob_and_tool() -> None:
    assert PolicyRule(path_glob="src/**").matches(_f(file="src/auth/x.py")) is True
    assert PolicyRule(path_glob="src/auth/**").matches(_f(file="src/other/x.py")) is False
    assert PolicyRule(tool="trivy").matches(_f(tool="bandit")) is False


def test_rule_min_severity() -> None:
    assert PolicyRule(min_severity="HIGH").matches(_f(sev=Severity.MEDIUM)) is False
    assert PolicyRule(min_severity="LOW").matches(_f(sev=Severity.MEDIUM)) is True


def test_rule_blocks_below_threshold() -> None:
    # MEDIUM < HIGH (nao bloquearia), mas a regra por CWE forca o bloqueio (elevacao)
    rep = Report((ScanResult("bandit", ScanStatus.OK, (_f(sev=Severity.MEDIUM),)),))
    assert GatePolicy().evaluate(rep).passed is True
    assert GatePolicy(rules=(PolicyRule(cwe="CWE-89"),)).evaluate(rep).passed is False


def test_blocked_by_rules_and_defs() -> None:
    assert blocked_by_rules((PolicyRule(cwe="CWE-89"),), _f()) is True
    assert blocked_by_rules((), _f()) is False


def test_config_parses_policy_rules() -> None:
    cfg = Config.from_dict({"policy": {"rules": [{"cwe": "CWE-89"}, {"path": "src/auth/**", "min_severity": "LOW"}]}})
    assert len(cfg.policy_rules) == 2
    assert cfg.policy_rules[0].cwe == "CWE-89" and cfg.policy_rules[1].path_glob == "src/auth/**"
