# Makefile for SonarQube Analysis Project

# Variables
PYTHON = python3
VENV = venv
VENV_BIN = $(VENV)/bin
PIP = $(VENV_BIN)/pip
FLASK = $(VENV_BIN)/flask
STREAMLIT = $(VENV_BIN)/streamlit
FLASK_APP = app.py
STREAMLIT_APP = sonarqube_analysis_app.py

# Phony targets
.PHONY: all venv install run run-flask run-streamlit test clean

# Default target
all: venv install run-flask run-streamlit

# Create virtual environment
venv:
	$(PYTHON) -m venv $(VENV)
	$(VENV_BIN)/python -m pip install --upgrade pip setuptools wheel

# Install dependencies
install: venv
	$(PIP) install -r requirements.txt

# Run the Flask application
run-flask: venv
	$(FLASK) run

# Run the Streamlit application
run-streamlit: venv
	$(STREAMLIT) run $(STREAMLIT_APP)

# Run both applications (Flask in background, Streamlit in foreground)
run: venv
	$(FLASK) run &
	$(STREAMLIT) run $(STREAMLIT_APP)

# Run tests (placeholder for now)
test: venv
	@echo "Running tests..."
	# Add your test command here, for example:
	# $(VENV_BIN)/pytest

# Clean up temporary files and virtual environment
clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	rm -rf $(VENV)

# Activate virtual environment (Note: this won't work directly from make, use as a reminder)
activate:
	@echo "To activate the virtual environment, use:"
	@echo "source $(VENV_BIN)/activate"

# Generate requirements file
requirements: venv
	$(PIP) freeze > requirements.txt

# Run the Flask application in debug mode
debug-flask: venv
	FLASK_ENV=development $(FLASK) run --debug

# Run the Streamlit application in debug mode
debug-streamlit: venv
	$(STREAMLIT) run $(STREAMLIT_APP) --logger.level=debug

# Help target
help:
	@echo "Available targets:"
	@echo "  make all              - Set up environment, install dependencies, and run both apps"
	@echo "  make venv             - Create a virtual environment"
	@echo "  make install          - Install dependencies in the virtual environment"
	@echo "  make run-flask        - Run the Flask application"
	@echo "  make run-streamlit    - Run the Streamlit application"
	@echo "  make run              - Run both Flask and Streamlit applications"
	@echo "  make test             - Run tests (placeholder)"
	@echo "  make clean            - Clean up temporary files and virtual environment"
	@echo "  make activate         - Show command to activate virtual environment"
	@echo "  make requirements     - Generate requirements.txt"
	@echo "  make debug-flask      - Run the Flask application in debug mode"
	@echo "  make debug-streamlit  - Run the Streamlit application in debug mode"
	@echo "  make help             - Show this help message"