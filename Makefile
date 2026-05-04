.PHONY: verify test test-invariants test-adversarial typecheck lint format coverage clean

PYTHON ?= python
VERIFY_RUNNER := scripts/verify.py

# ----------------------------------------------------------------------------
# verify — full quality gate. Must be green before any PR merges.
#          Mirrors what CI runs. Run this locally before pushing.
# ----------------------------------------------------------------------------
verify:
	$(PYTHON) $(VERIFY_RUNNER) verify

# ----------------------------------------------------------------------------
# Individual targets — use during development
# ----------------------------------------------------------------------------
test:
	$(PYTHON) $(VERIFY_RUNNER) test

test-invariants:
	$(PYTHON) $(VERIFY_RUNNER) test-invariants

test-adversarial:
	$(PYTHON) $(VERIFY_RUNNER) test-adversarial

typecheck:
	$(PYTHON) $(VERIFY_RUNNER) typecheck

lint:
	$(PYTHON) $(VERIFY_RUNNER) lint

format:
	$(PYTHON) $(VERIFY_RUNNER) format

coverage:
	$(PYTHON) $(VERIFY_RUNNER) coverage

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
