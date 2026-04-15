# LogAI-Analyst Makefile
# Comandos comunes para desarrollo y despliegue

.PHONY: help install test train docker docker-compose lint clean

# Variables
PYTHON := python
PIP := pip
DOCKER_IMAGE := logai-analyst

help: ## Muestra esta ayuda
	@echo "Comandos disponibles:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Instala dependencias desde requirements.txt
	$(PIP) install -r requirements.txt

train: ## Entrena el modelo de ML con datos sintéticos
	$(PYTHON) train_model.py

test: ## Ejecuta todos los tests con pytest
	$(PYTHON) -m pytest tests/ -v

test-cov: ## Ejecuta tests con cobertura
	$(PYTHON) -m pytest tests/ -v --cov=src --cov-report=html --cov-report=term

dev: ## Inicia el servidor en modo desarrollo (con auto-reload)
	$(PYTHON) -c "from main import app; import uvicorn; uvicorn.run(app, host='127.0.0.1', port=8000, reload=True)"

run: ## Inicia el servidor en modo producción
	$(PYTHON) -c "from main import app; import uvicorn; uvicorn.run(app, host='0.0.0.0', port=8000)"

docker-build: ## Construye la imagen Docker
	docker build -t $(DOCKER_IMAGE):latest .

docker-run: ## Ejecuta el contenedor Docker (requiere .env)
	docker run -p 8000:8000 --env-file .env $(DOCKER_IMAGE):latest

docker-compose-up: ## Inicia con Docker Compose (incluye Redis para rate limiting)
	docker-compose up -d

docker-compose-down: ## Detiene Docker Compose
	docker-compose down

docker-compose-logs: ## Muestra logs de Docker Compose
	docker-compose logs -f

lint: ## Ejecuta linting con flake8 y mypy
	$(PYTHON) -m flake8 src/ --max-line-length=100 --extend-ignore=E203,W503
	$(PYTHON) -m mypy src/ --ignore-missing-imports

format: ## Formatea el código con black y isort
	$(PYTHON) -m black src/ tests/ --line-length=100
	$(PYTHON) -m isort src/ tests/ --profile=black

clean: ## Limpia archivos temporales y cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .coverage -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage

health-check: ## Verifica el endpoint de health
	curl -s http://localhost:8000/health | jq .

analyze-sample: ## Ejecuta análisis de ejemplo con sample.log
	curl -X POST http://localhost:8000/analyze \
		-H "X-API-KEY: $$API_KEY" \
		-F "file=@tests/sample.log" | jq .
