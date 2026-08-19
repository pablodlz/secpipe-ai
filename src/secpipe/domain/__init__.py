"""Domínio puro: o CONTRATO de achados e a RÉGUA (política). SEM I/O, SEM libs externas."""

from .models import Finding, Report, ScanResult, ScanStatus, Severity
from .policy import GateDecision, GatePolicy

__all__ = [
    "Finding", "Report", "ScanResult", "ScanStatus", "Severity",
    "GateDecision", "GatePolicy",
]
