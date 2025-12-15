## Contributing to `social-core`

Thank you for your interest in contributing to `social-auth-core` (the `social_core` package)!  
This document explains how to set up your environment, make changes, run tests, and propose them for inclusion.

The short version:

- **Use Python 3.10+**
- **Create an isolated environment**
- **Install the project in editable mode with dev extras**
- **Run tests and type checks before opening a PR**

---

## 1. Project overview

This repository contains the **core** of the Python Social Auth ecosystem:

- The main package lives in `social_core/`.
- Authentication backends live in `social_core/backends/`.
- Tests live in `social_core/tests/`.

If you are changing authentication behaviour or adding/updating a backend, you will almost always need to:

- Touch code in `social_core/backends/...`
- Add or adjust tests in `social_core/tests/backends/...`

---

## 2. Environment setup

### 2.1. Requirements

- Python **3.10 or newer** (the project supports several 3.x versions, but tests are driven primarily from 3.10+).
- A recent version of `pip`.
- It is recommended (and expected in CI) to use `tox` and `uv` for running the full matrix, but you can use plain `pytest` locally.

### 2.2. Create and activate a virtual environment

On most systems:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 2.3. Install the package (with dev extras)

From the project root:

```bash
pip install -e .[dev,all]
```

This installs the library in editable mode along with the development and “all backends” extras, including:

- `pytest`, `pytest-xdist`, `pytest-cov`, `responses`
- `mypy`, `pyright`
- `flake8`, `ruff`
- type stubs and related tooling

---

## 3. Running tests

The project uses **pytest** for tests, and **tox** for multi‑environment testing and type checking.

### 3.1. Run the test suite directly with pytest

Once you have installed `-e .[dev,all]`, you can run:

```bash
pytest
```

Pytest configuration is in `pyproject.toml` (`[tool.pytest.ini_options]`), and by default it:

- Measures coverage for the `social_core` package.
- Produces an XML coverage report.
- Reports the 10 slowest tests.

#### Running a subset of tests

- **Single test file**:

  ```bash
  pytest social_core/tests/test_utils.py
  ```

- **All backend tests**:

  ```bash
  pytest social_core/tests/backends
  ```

- **Single test within a file**:

  ```bash
  pytest social_core/tests/test_utils.py::test_some_function
  ```

### 3.2. Run the full test matrix with tox (recommended before PRs)

Install `tox` and `uv`:

```bash
pip install tox uv
```

Run all configured environments:

```bash
tox
```

This will:

- Run tests on multiple Python versions: `py310, py311, py312, py313, py314`.
- Run pyright type checks in dedicated environments: `py310-pyright`, `py313-pyright`.
- Use `uv` to install dependencies (see `tox.ini`).

Run a single environment (e.g. Python 3.12 only):

```bash
tox -e py312
```

Run only pyright:

```bash
tox -e py310-pyright
tox -e py313-pyright
```

---

## 4. Linting and type checking

While CI will run linters and type checkers, it is helpful to run them locally where possible.

### 4.1. Ruff (preferred linter)

Ruff is configured in `pyproject.toml` and is the main code-quality tool.

Run Ruff on the whole project:

```bash
ruff check .
```

To auto‑fix what can be fixed safely:

```bash
ruff check . --fix
```

### 4.2. Flake8

Flake8 is also part of the dev dependencies. To run it:

```bash
flake8 social_core
```

### 4.3. Type checking with mypy

Mypy configuration lives under `[tool.mypy]` in `pyproject.toml`.

Run mypy:

```bash
mypy social_core
```

### 4.4. Type checking with pyright

To match CI’s behaviour you can either:

- Use **tox** (see above): `tox -e py310-pyright` / `tox -e py313-pyright`, or
- Run pyright directly:

  ```bash
  pyright
  ```

---

## 5. Coding style and guidelines

- **Keep backwards compatibility**: This package is widely used. Avoid breaking changes to public APIs. If a change is inherently breaking, open an issue first and discuss it.
- **Add tests** for any new feature or bugfix. Try to cover edge cases specific to the backend or behaviour you are touching.
- **Follow existing patterns**: Reuse existing helper functions and patterns within `social_core` (particularly in backends and pipeline modules).
- **Type hints**: New or significantly refactored code should include type annotations where reasonable. Do not introduce type errors in `mypy` or `pyright`.
- **Documentation**: If your change affects behaviour that is user‑facing or visible in docs, make sure to update relevant docstrings or external documentation as appropriate.

---

## 6. Adding or modifying backends

If you are contributing a new backend or updating an existing one:

- Follow the structure and naming patterns of other backends in `social_core/backends/`.
- Include configuration examples and parameter names consistent with upstream documentation of the provider.
- Add tests under `social_core/tests/backends/`:
  - Use existing backend tests as a template.
  - Ensure your tests do not rely on real external services (use mocks/responses).

---

## 7. Submitting changes

1. **Fork** the repository on GitHub.
2. **Create a branch** for your work:

   ```bash
   git checkout -b feature/my-change
   ```

3. **Make your changes** in small, logical commits.
4. **Run tests and checks** locally:
   - At minimum: `pytest`.
   - Ideally: `tox` to run the full matrix and type checks.
5. **Push your branch** to your fork.
6. **Open a pull request** against the main repository:
   - Describe what the change does and why it is needed.
   - Reference any related issues.
   - Mention potential breaking changes or migration notes, if any.

Maintainers may request adjustments (tests, documentation, code style) before merging. Please be patient and responsive during review.

---

## 8. Reporting issues and requesting features

If you have found a bug or would like to request a feature:

- Search existing issues on GitHub to see if it has already been reported or discussed.
- Include:
  - Your Python version.
  - The version of `social-auth-core` you are using.
  - A minimal reproducible example if possible.
  - Any relevant tracebacks, logs, or external provider details.

Clear reports make it much easier for maintainers and contributors to help.

---

## 9. Code of conduct

Please be respectful and constructive in all interactions.  
Be welcoming to new contributors, and assume good faith. The goal is to make `social-auth-core` better for everyone.


