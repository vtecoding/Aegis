"""Intent layer package for future parsing and normalisation work.

This package is intentionally implementation-empty in the current Phase 1
pipeline. Raw boundary intent is currently represented by
``aegis.contracts.intent.RawIntent`` and semantic checks live in
``aegis.validation``.

Do not add parsing, LLM, natural-language, or adapter behaviour here without a
separate intent-v1 specification, tests, and release gate.
"""

__all__: list[str] = []
