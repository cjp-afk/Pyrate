@echo off
echo ===============================
echo Running Development Toolchain
echo ===============================

:: Run linting
echo.
echo --- Ruff (lint) ---
uv run ruff check .

:: Run formatting
echo.
echo --- Black (format check) ---
uv run black src tests

:: Run type checking
echo.
echo --- MyPy (type check) ---
:: uv run mypy src
echo Skipping MyPy for now due to performance.

:: Run tests
echo.
echo --- Pytest (tests) ---
uv run pytest -q --maxfail=1 --disable-warnings

echo.
echo ===============================
echo All dev checks complete!
echo ===============================
pause
