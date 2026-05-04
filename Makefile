.PHONY: verify test test-invariants test-adversarial typecheck lint format coverage clean

PYTHON := python
SRC    := src
TESTS  := tests

# ----------------------------------------------------------------------------
# verify — full quality gate. Must be green before any PR merges.
#          Mirrors what CI runs. Run this locally before pushing.
# ----------------------------------------------------------------------------
verify: typecheck lint
	ruff format --check $(SRC) $(TESTS)
	pytest $(TESTS) --cov=$(SRC) --cov-report=term-missing --cov-fail-under=90
	pytest $(TESTS)/invariants -v --tb=short

# ----------------------------------------------------------------------------
# Individual targets — use during development
# ----------------------------------------------------------------------------
test:
	pytest $(TESTS)

test-invariants:
	pytest $(TESTS)/invariants -v --tb=short

test-adversarial:
	pytest $(TESTS)/adversarial -v --tb=short

typecheck:
	pyright --project pyproject.toml

lint:
	ruff check $(SRC) $(TESTS)

format:
	ruff format $(SRC) $(TESTS)

coverage:
	pytest $(TESTS) --cov=$(SRC) --cov-report=term-missing --cov-report=html

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
