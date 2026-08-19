.DEFAULT_GOAL := help
PY := python
.PHONY: help setup lint type test sec audit check dogfood
help: ## Lista alvos
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
setup: ## Instala deps de dev
	$(PY) -m pip install -e ".[dev]"
lint: ## Ruff (inclui regras S/bandit)
	ruff check src tests
type: ## mypy strict
	mypy src
test: ## pytest (unit + architecture)
	pytest -q
sec: ## SAST bandit
	bandit -q -r src
audit: ## SCA pip-audit
	pip-audit
check: lint type test sec ## Gate local completo
dogfood: ## Roda o próprio secpipe em si mesmo (self-hosting)
	$(PY) -m secpipe.cli scan .
