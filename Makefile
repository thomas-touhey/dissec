#!/usr/bin/make -f

help:
	@echo "Please select a target. Check the Makefile for more info."

install:
	@echo "Installing poetry and dependencies."
	@pip install poetry==2.2.1
	@poetry install
	@poetry run pre-commit install -t pre-commit -t commit-msg

lint:
	@poetry run pre-commit run --all-files

build:
	@poetry build

test:
	@rm -rf htmlcov
	@poetry run pytest $(O) $(SPECIFIC_TESTS)
	@echo "HTML coverage is available under the following directory:"
	@echo "file://$(realpath .)/htmlcov/index.html"

clean:
	@echo "Cleaning build and cache directories."
	@rm -rf build .coverage htmlcov .mypy_cache .pytest_cache

.PHONY: help install lint build test clean
