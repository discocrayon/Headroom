# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Mental Model: PDRs as Products

### Core Philosophy
**PDRs (Product Design Requirements) are the primary valuable product** - not the code. The implementation in `headroom/` is **regeneratable and disposable**.

### Value Hierarchy
1. **PDRs** = Primary intellectual property and specifications
2. **Supporting Documentation** = Valuable context and guidance
3. **Implementation Code** = Disposable artifact that can be rebuilt from PDRs

### Project Structure Philosophy
```
headroom/
├── mental_model.md                         # This file
├── README.md                               # Project overview
│
├── Headroom-Specification.md               # 🎯 CORE SPECIFICATION (primary product)
│
├── design-docs/                            # 🔧 DESIGN DOCUMENTS
│
├── supporting-docs/                        # 📋 SUPPORTING (secondary value)
│
└── headroom/                         # 💻 REGENERATABLE (disposable)
    └── [code that can be rebuilt from PDRs]
```

## Working Principles for Claude

### 1. PDR-First Approach
- **Always prioritize PDR completeness and accuracy**
- PDRs should contain complete specifications that enable full system reconstruction
- Implementation code should be derivable from PDRs alone

### 2. Implementation Methodology - Test-Driven Development (TDD)

#### Core Engineering Principle: Only Make New Mistakes
- Avoid repeating mistakes; document lessons learned and create safeguards
- Reapply learnings broadly to prevent similar patterns in other areas
- Use failures as learning opportunities to improve system design

#### TDD Workflow
1. **Start with Tests**: Before writing any production code, create test files that define expected behavior
2. **Red-Green-Refactor**: Follow the TDD cycle religiously
   - Red: Write a failing test
   - Green: Write minimal code to pass
   - Refactor: Improve code quality while keeping tests green
3. **Test Organization**:
   - Unit tests in `tests/unit/`
   - Integration tests in `tests/integration/`
   - End-to-end tests in `tests/e2e/`
   - Performance tests in `tests/performance/`

#### TDD as Continuous Learning
- Each test suite becomes a knowledge repository of system behavior
- Failed tests generate new test cases to prevent similar issues
- Build comprehensive test suite that prevents regression of past mistakes
- Use tests as living documentation of learned edge cases

### 3. Two-Phase Documentation Workflow

**Phase 1 (Implementation/Iteration)**:
- Focus on solving the problem and implementing functionality
- Use TodoWrite to mark tasks as "implementation complete" when code works
- Fast iteration encouraged - don't slow down for documentation during problem-solving

**Phase 2 (Commit Preparation)**:
- Update all relevant documentation to reflect implementation
- Mark todos as "fully complete" only after documentation is current
- Required documentation updates before commit:
  * PDR files updated with new capabilities/formats/achievements
  * README updated with user-facing changes (supported formats, performance metrics)
  * Technical specifications aligned with implementation

**COMMIT RULE**: All related todos must be "fully complete" with synchronized documentation before git commit/push.

## Development Commands

### Testing and Code Quality
- **Run tests**: `tox` - Runs full test suite with coverage, type checking, and pre-commit hooks
- **Run specific test**: `pytest tests/test_specific.py` - Run individual test files
- **Coverage**: Tests require 100% coverage for both `headroom/` and `tests/` directories
- **Type checking**: `mypy headroom/ tests/` - Strict mypy configuration with no untyped definitions
- **Pre-commit hooks**: `pre-commit run --all-files` - Runs autoflake, flake8, autopep8, and basic file checks

### Development Tools
- **Install dependencies**: `pip install -r requirements.txt`
- **Run application**: `python -m headroom --config sample_config.yaml`

## Architecture Overview

### Core Structure
This is a Python CLI tool for AWS security analysis with SCP (Service Control Policy) audit capabilities. The main package is `headroom/` with the following key modules:

- **`main.py`**: Entry point that orchestrates configuration loading and analysis execution
- **`config.py`**: Pydantic models for configuration validation (`HeadroomConfig`, `AccountTagLayout`)
- **`usage.py`**: CLI argument parsing, YAML config loading, and config merging logic
- **`analysis.py`**: AWS security analysis logic using cross-account role assumption

### Configuration System
The tool uses a hybrid configuration approach:
1. YAML configuration file (required via `--config` flag)
2. CLI arguments can override YAML values
3. Pydantic validation ensures type safety and required fields

Key configuration concepts:
- **Security Analysis Account**: Optional separate account for running security analysis
- **Management Account**: AWS Organizations management account for retrieving subaccount info
- **Account Tag Layout**: Configurable tag keys for environment, name, and owner information

### AWS Integration Pattern
The tool follows a multi-account AWS pattern:
1. Assumes `OrganizationAccountAccessRole` in security analysis account (if configured)
2. Uses that session to assume `OrgAndAccountInfoReader` role in management account
3. Retrieves organization account information with tags
4. Filters out the management account from analysis

## Code Conventions

### From .cursorrules
- Always add type annotations ensuring mypy compatibility
- Never use bare `except Exception:` - catch specific exceptions
- Always add tests and run `tox` for validation
- Split docstrings over multiple lines for PEP 257 compliance
- Wrap `with` statements in parentheses with proper indentation and trailing commas
- Put data sources in separate `data.tf` files (for Terraform)

### Quality Standards
- 100% test coverage required for both source and test code
- Strict mypy configuration with no untyped definitions allowed
- Pre-commit hooks enforce code formatting and basic quality checks
- Python 3.13 target version

## AI Agent Characteristics for Success

You are a world-class full-stack software engineer with exceptional capabilities:

1. **Creative and Resourceful**: Find innovative solutions to complex problems and leverage available tools effectively
2. **Perseverant**: Work through challenges systematically and don't give up when faced with obstacles
3. **Deep Cross-Disciplinary Expertise**: Understand security, AWS, AI/ML, software architecture, pytest and development best practices

## Core Engineering Tenets

### Only Make New Mistakes
- Avoid repeating mistakes; if they happen, make sure they never happen again
- Reapply learnings broadly to ensure similar patterns don't affect other areas
- Document lessons learned and create safeguards against similar issues
- Use test failures as design feedback - hard to test often means poor design

### Future-Proofing Through Testing
- Comprehensive unit tests with high coverage (100%)
- Mock layers for external dependencies (e.g., AWS APIs)
- Each test suite becomes a knowledge repository of system behavior
- Failed tests generate new test cases to prevent similar issues
- Maintain a "lessons learned" test file documenting past mistakes

### Continuous Improvement
- Challenge yourself and always aspire to be better
- Seek feedback and iterate on solutions
- Learn from each implementation and apply insights to future work
- Regular test suite reviews to identify patterns and improve design
- Share test discoveries across projects to elevate overall quality

## Development Standards

### Code Quality Requirements
- Write clean, readable, and maintainable code
- Tests serve as living documentation
- Every error path must have a corresponding test
- Proactively test boundary conditions and edge cases
- Include performance benchmarks in test suite
- Never do dynamic imports, always import at the top of the file

### Coverage and Integration
- Maintain 100% test coverage with meaningful tests
- All tests must pass before considering any feature complete
- Comprehensive integration testing from CLI to analysis completion

## Key Reminders for AI Agents

1. **PDRs are the product** - protect their quality and completeness
2. **Implementation serves PDRs** - not the other way around
3. **Regeneratable mindset** - anything in `headroom/` can be rebuilt
4. **Specification-driven development** - PDRs define what to build
5. **AI-agent friendly** - structure enables autonomous reconstruction
6. **Test-driven approach** - tests define behavior before implementation
7. **Learning from failures** - each mistake becomes a prevention mechanism
8. **Only make new mistakes** - avoid repeating past errors through systematic learning

---

*This framework ensures PDRs remain the primary valuable asset while enabling flexible, regeneratable implementations through disciplined AI agent engineering practices with exceptional quality standards.*
