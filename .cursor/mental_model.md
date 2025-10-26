# Headroom Project Mental Model

This file provides guidance when working with this project.

## Mental Model: PDRs as Products

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

### 2. PDR Organization
- **Flat structure** for PDRs at root level (high visibility)
- **Categorization by prefix** (Parser-, Validation-, etc.)
- **Core Specification** (AI-Scanner-Specification.md) as the primary entry point

### 3. Supporting Documentation
- Place in `supporting-docs/` subfolder
- Valuable but secondary to PDRs
- Should support and reference PDRs, not replace them

### 4. Implementation Code
- Treat as **disposable and regeneratable**
- Should be buildable from PDRs using CLAUDE.md implementation framework
- Clean separation from PDR specifications

### 5. Quality Standards
- PDRs must be **complete, accurate, and implementation-independent**
- Each PDR should enable autonomous reconstruction by AI agents
- Maintain traceability between PDRs and implementation decisions

## AI Agent Implementation Framework

### Core Engineering Principles

#### 1. Only Make New Mistakes
- Avoid repeating mistakes; document lessons learned and create safeguards
- Reapply learnings broadly to prevent similar patterns in other areas
- Use failures as learning opportunities to improve system design

#### 2. Test-Driven Development (TDD) Alignment
- **Write tests BEFORE implementation** to define expected behavior
- Each test failure is a learning opportunity - capture why it failed
- Build comprehensive test suite that prevents regression of past mistakes
- Use tests as living documentation of learned edge cases
- Create property-based tests to discover new failure modes proactively

#### 3. Future-Proofing Through Testing
- Comprehensive unit tests with high coverage (100%)
- Mock layers for external dependencies (e.g., AWS APIs)

### Implementation Methodology

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
4. **Coverage Requirements**: Maintain 90%+ test coverage with meaningful tests
5. **Continuous Integration**: All tests must pass before considering any feature complete

#### Development Standards
- **Code Quality**: Write clean, readable, and maintainable code
- **Documentation**: Tests serve as living documentation
- **Error Handling**: Every error path must have a corresponding test
- **Edge Cases**: Proactively test boundary conditions and edge cases
- **Performance**: Include performance benchmarks in test suite

#### Two-Phase Documentation Workflow

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

### Build Process & Implementation Directives

#### Primary Implementation Task
Implement the Headroom security tool according to the Product Design Requirements defined in `Headroom-Specification.md`.

**Implementation Location**: Create all implementation files in the `headroom/` folder to keep the project organized and separate from documentation.

**TDD Requirement**: Begin by creating a comprehensive test suite that defines the scanner's behavior before implementing any functionality.

#### AI Agent Characteristics for Success
1. **Creative and Resourceful**: Find innovative solutions to complex problems and leverage available tools effectively
2. **Perseverant**: Work through challenges systematically and don't give up when faced with obstacles
3. **Deep Cross-Disciplinary Expertise**: Understand security, AWS, software architecture, and development best practices

#### Continuous Improvement Mindset
- Seek feedback and iterate on solutions
- Stay current with latest AWS and pytest documentation
- Optimize performance and cost continuously
- Learn from each implementation and apply insights to future work

**TDD as Continuous Learning**:
- Each test suite becomes a knowledge repository of system behavior
- Failed tests generate new test cases to prevent similar issues
- Maintain a "lessons learned" test file documenting past mistakes
- Regular test suite reviews to identify patterns and improve design
- Share test discoveries across projects to elevate overall quality

## Key Reminders for AI Agents

1. **PDRs are the product** - protect their quality and completeness
2. **Implementation serves PDRs** - not the other way around
3. **Regeneratable mindset** - anything in `implementation/` can be rebuilt
4. **Specification-driven development** - PDRs define what to build
5. **AI-agent friendly** - structure enables autonomous reconstruction
6. **Test-driven approach** - tests define behavior before implementation
7. **Learning from failures** - each mistake becomes a prevention mechanism

---

*This mental model ensures PDRs remain the primary valuable asset while enabling flexible, regeneratable implementations through disciplined AI agent engineering practices.*
