# Makefile for SonarQube Analysis Project

# Variables
PYTHON = python3
VENV = venv
VENV_BIN = $(VENV)/bin
PIP = $(VENV_BIN)/pip
FLASK = $(VENV_BIN)/flask
STREAMLIT = $(VENV_BIN)/streamlit

STREAMLIT_APP = app.py

# Phony targets
.PHONY: all venv install run run-flask run-streamlit test clean

# Default target
all: venv install run-streamlit

# Create virtual environment
venv:
	$(PYTHON) -m venv $(VENV)
	. $(VENV_BIN)/activate && $(PYTHON) -m pip install --upgrade pip setuptools wheel

# Install dependencies
install: venv
	. $(VENV_BIN)/activate && $(PIP) install -r requirements.txt

# Run the Streamlit application
run-streamlit: venv install
	. $(VENV_BIN)/activate && $(STREAMLIT) run $(STREAMLIT_APP)

# Run both applications (Flask in background, Streamlit in foreground)
run: venv install
	. $(VENV_BIN)/activate && $(FLASK) run &
	. $(VENV_BIN)/activate && $(STREAMLIT) run $(STREAMLIT_APP)

# Clean up temporary files and virtual environment
clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	rm -rf $(VENV)

# Help target
help:
	@echo "Available targets:"
	@echo "  make all              - Set up environment, install dependencies, and run Streamlit app"
	@echo "  make venv             - Create a virtual environment"
	@echo "  make install          - Install dependencies in the virtual environment"
	@echo "  make run-streamlit    - Run the Streamlit application"
	@echo "  make run              - Run both Flask and Streamlit applications"
	@echo "  make clean            - Clean up temporary files and virtual environment"
	@echo "  make help             - Show this help message"