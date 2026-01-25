#!/bin/bash
set -e

echo "Installing test dependencies..."
pip install -r requirements-dev.txt

echo ""
echo "Running tests..."
pytest tests/ --cov=main --cov-report=term-missing --cov-report=html

echo ""
echo "Test coverage report generated in htmlcov/index.html"
