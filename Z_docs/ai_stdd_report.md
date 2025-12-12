# AI-assisted STDD Report – FairRideApp

## 1. Objective

The purpose of this report is to describe how **AI assistants** are integrated into the **Secure Test-Driven Development (STDD)** process for the *FairRideApp* project.

The main goal is to keep AI **under control**, not in control: AI supports the human team, but final responsibility for security and correctness remains with the developers.

---

## 2. Role of AI in the STDD Cycle

The STDD activity diagram (`stdd_security_diagram.puml`) defines a five-lane process:

1. **System Developer**
2. **Security Engineer**
3. **AI Assistant**
4. **Testing & Analysis Tools**
5. **Repository / CI Pipeline**

AI is explicitly restricted to **Phase 3 – First Generation**, after security requirements and models are defined.

### 2.1 Inputs provided to the AI

Before AI is used, the following artefacts are prepared by humans:

- **Secure Tropos model** (`secure_tropos_model.puml`)
- **DSM model** (`dsm_model.puml`)
- **Security mechanisms definition** (`security_mechanisms.md`)
- A natural-language description of:
  - FairRideApp objectives.
  - Domain concepts (trips, pricing, users).
  - Security requirements R1–R4.

These artefacts encode the **security decisions** that AI must respect.

### 2.2 Tasks performed by the AI Assistant

Within the STDD cycle, the AI Assistant performs two controlled tasks:

1. **Generate initial code (text-only prompt)**
   - From the natural-language description, AI proposes:
     - Module structure (`sud/` package),
     - Basic classes and functions (crypto, auth, validation, pricing, trip security).

2. **Generate improved secure code (with PlantUML and tests)**
   - AI receives the PlantUML models as additional context:
     - `secure_tropos_model.puml`
     - `dsm_model.puml`
   - AI refines the code so that:
     - Encryption, input validation and logging follow the patterns from the DSM.
     - Unit tests are generated for the critical security behaviours.

The output of the AI step is considered **a draft**, not final code.

---

## 3. Human Oversight and Control

To avoid blind trust in AI-generated artefacts, the process enforces the following controls:

- **Security Engineer review**
  - Checks that the generated code is consistent with the Tropos and DSM models.
  - Confirms that each requirement R1–R4 has at least one corresponding mechanism in `sud/` and at least one test in `tests/`.

- **Testing & Analysis**
  - Unit tests, static analysis and vulnerability scanning are mandatory before merging.
  - If vulnerabilities are found, the process loops back:
    - Models and prompts are refined by humans.
    - AI may be used again, but only inside this controlled loop.

- **Repository / CI Policies**
  - Only code that passes all tests and security checks can be tagged as a release.
  - AI cannot push directly to `main`; all changes must go through human review.

---

## 4. Risks and Mitigations

### 4.1 Hallucinated Security

**Risk:** AI invents non-existent security guarantees or misuses libraries.

**Mitigation:**

- Use only APIs and libraries that the team understands.
- Cross-check all critical security code against official documentation.
- Require at least one **manual security review** per iteration.

### 4.2 Incomplete Test Coverage

**Risk:** AI generates superficial tests that do not cover edge cases.

**Mitigation:**

- Developers add **negative tests** and boundary cases manually.
- Security Engineer reviews test coverage focusing on:
  - Encryption round-trip,
  - Input validation rejections,
  - Authentication failures,
  - Logging of suspicious events.

### 4.3 Model–Code Drift

**Risk:** As the code evolves, the PlantUML models stop reflecting reality.

**Mitigation:**

- Any new security-relevant change in the codebase requires a short update of:
  - `dsm_model.puml`
  - `security_mechanisms.md`
- The STDD diagram explicitly contains the step:
  - “Refine PlantUML models if needed”.

---

## 5. Conclusion

AI is used as a **productivity amplifier** in FairRideApp, not as a replacement for secure software engineering. By constraining AI to:

- Work **after** security requirements and models are defined,
- Operate inside a **tested and monitored** pipeline,
- Stay under **human review and approval**,

the project aligns with the STDD philosophy: *security-aware tests and mechanisms drive the development*, and AI simply helps to fill in the implementation details faster.
