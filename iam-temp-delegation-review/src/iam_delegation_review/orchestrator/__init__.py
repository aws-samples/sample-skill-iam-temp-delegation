"""orchestrator — runs the pipeline stages in order, handles short-circuit.

Plain-code ordering of the stages (gate → provable → report). No LLM decides
stage order. Honors the hard-fail short-circuit and always passes rendered
copies to syntax-sensitive stages.
"""

from __future__ import annotations

from ._intake import BoundaryConflictError, classify
from ._pipeline import run_pipeline
from ._report import format_report
from ._types import ClassifiedBundle, Operation, Report

__all__ = [
    "Operation",
    "ClassifiedBundle",
    "Report",
    "run_pipeline",
    "format_report",
    "BoundaryConflictError",
    "classify",
]
