import ast
from pathlib import Path

from .models import Evidence, Finding


AI_IMPORTS = {
    "openai",
    "anthropic",
    "google.generativeai",
    "google.genai",
    "langchain",
    "langchain_core",
    "langchain_openai",
    "llama_index",
    "transformers",
    "ollama",
    "litellm",
}

MODEL_CALL_NAMES = {
    "chat",
    "completion",
    "completions",
    "generate",
    "generate_content",
    "invoke",
    "predict",
    "complete",
    "chat_completion",
    "create",
}

DATA_SOURCE_NAMES = {
    "request",
    "requests",
    "input",
    "user_input",
    "prompt",
    "email",
    "phone",
    "address",
    "customer",
    "patient",
    "employee",
    "user",
}

SENSITIVE_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "ssn",
    "aadhaar",
    "pan",
    "credit_card",
    "card_number",
    "cvv",
    "dob",
    "date_of_birth",
    "medical_record",
    "patient_record",
    "health_record",
}

DATA_SINK_NAMES = {
    "print",
    "logging",
    "logger",
    "log",
    "write",
    "send",
    "post",
    "put",
    "requests",
    "httpx",
    "fetch",
    "info",
    "warning",
    "error",
    "debug",
    "exception",
    "critical",
    "urlopen",
}

CONTROL_MAP = {
    "AEGIS-SEC-001": {
        "control_id": "GOV-SEC-SECRET-001",
        "control": "Secrets must not be embedded in privileged AI configuration or source code.",
        "domain": "Secret Management",
    },
    "AEGIS-AI-001": {
        "control_id": "GOV-AI-PROMPT-001",
        "control": "Privileged AI instructions must not contain hardcoded secrets.",
        "domain": "AI Prompt Security",
    },
    "AEGIS-AI-002": {
        "control_id": "GOV-AI-INPUT-001",
        "control": "Untrusted input crossing into privileged AI instructions requires explicit trust-boundary handling.",
        "domain": "AI Input Governance",
    },
    "AEGIS-AI-003": {
        "control_id": "GOV-DATA-PII-001",
        "control": "Sensitive personal data flows to logging, model, or network sinks require explicit governance controls.",
        "domain": "Data Governance",
    },
    "AEGIS-AI-004": {
        "control_id": "GOV-RAG-ACCESS-001",
        "control": "Retrieved data requires an observable authorization boundary.",
        "domain": "RAG Governance",
    },
    "AEGIS-AI-017": {
        "control_id": "GOV-AI-OUTPUT-001",
        "control": "AI-generated output must not directly reach dangerous execution or data-access sinks.",
        "domain": "AI Output Governance",
    },
    "AEGIS-AGENCY-001": {
        "control_id": "GOV-AGENT-AUTH-001",
        "control": "Agent capabilities must follow least-privilege and controlled-agency principles.",
        "domain": "Agent Governance",
    },
}


def _relative(path, project):
    return Path(path).resolve().relative_to(Path(project).resolve()).as_posix()


def _name_from_expr(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _name_from_expr(node.func)
    return None


def _module_from_import(node):
    if isinstance(node, ast.Import):
        return [x.name for x in node.names]
    if isinstance(node, ast.ImportFrom):
        return [node.module] if node.module else []
    return []


def _is_ai_module(name):
    if not name:
        return False
    return any(
        name == base or name.startswith(base + ".")
        for base in AI_IMPORTS
    )


def _call_name(node):
    if isinstance(node, ast.Call):
        return _name_from_expr(node.func)
    return None


def _literal_text(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def discover_ai_systems(project):
    project = Path(project).resolve()
    systems = []

    for path in sorted(project.rglob("*.py"), key=lambda p: p.as_posix()):
        if any(
            part in {
                ".git",
                ".venv",
                "venv",
                "node_modules",
                "__pycache__",
                ".mypy_cache",
                ".pytest_cache",
                ".tox",
            }
            for part in path.parts
        ):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError):
            continue

        imports = []
        ai_names = set()
        model_calls = []

        for node in ast.walk(tree):
            modules = _module_from_import(node)

            for module in modules:
                if _is_ai_module(module):
                    imports.append(module)

                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if _is_ai_module(alias.name):
                                ai_names.add(alias.asname or alias.name.split(".")[0])

                    elif isinstance(node, ast.ImportFrom):
                        if _is_ai_module(node.module or ""):
                            for alias in node.names:
                                ai_names.add(alias.asname or alias.name)

            if isinstance(node, ast.Call):
                call = _call_name(node)
                if not call or call.lower() not in MODEL_CALL_NAMES:
                    continue

                # A model invocation is only governance evidence when the
                # source file also contains a statically observable AI-library
                # import. Generic calls such as client.create(...) are not
                # sufficient evidence on their own.
                if imports:
                    model_calls.append(
                        {
                            "name": call,
                            "line": node.lineno,
                        }
                    )

        if not imports and not model_calls:
            continue

        evidence_line = 1
        evidence_detection = "AI library import detected"

        if model_calls:
            evidence_line = model_calls[0]["line"]
            evidence_detection = (
                "AI/model invocation detected: "
                + model_calls[0]["name"]
            )
        elif imports:
            for node in ast.walk(tree):
                modules = _module_from_import(node)
                if any(_is_ai_module(m) for m in modules):
                    evidence_line = node.lineno
                    evidence_detection = (
                        "AI library import detected: "
                        + sorted(set(imports))[0]
                    )
                    break

        systems.append(
            {
                "name": path.stem,
                "type": "AI_SYSTEM",
                "source": {
                    "file": _relative(path, project),
                    "line": evidence_line,
                },
                "evidence": {
                    "file": _relative(path, project),
                    "line": evidence_line,
                    "detection": evidence_detection,
                },
                "detection": evidence_detection,
                "ai_libraries": sorted(set(imports)),
                "model_invocations": model_calls,
            }
        )

    systems.sort(
        key=lambda x: (
            x["source"]["file"],
            x["source"]["line"],
            x["name"],
        )
    )
    return systems

def build_data_map(project):
    project = Path(project).resolve()
    flows = []

    for path in sorted(project.rglob("*.py"), key=lambda p: p.as_posix()):
        if any(
            part in {
                ".git",
                ".venv",
                "venv",
                "node_modules",
                "__pycache__",
                ".mypy_cache",
                ".pytest_cache",
                ".tox",
            }
            for part in path.parts
        ):
            continue

        try:
            tree = ast.parse(
                path.read_text(encoding="utf-8", errors="ignore"),
                filename=str(path),
            )
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            sink = _call_name(node)
            if not sink:
                continue

            sink_lower = sink.lower()

            if sink_lower not in DATA_SINK_NAMES:
                continue

            for argument in node.args:
                source_name = _name_from_expr(argument)
                if not source_name:
                    continue

                source_lower = source_name.lower()

                if (
                    source_lower in DATA_SOURCE_NAMES
                    or source_lower in SENSITIVE_NAMES
                    or any(x in source_lower for x in SENSITIVE_NAMES)
                ):
                    classification = (
                        "SENSITIVE"
                        if (
                            source_lower in SENSITIVE_NAMES
                            or any(x in source_lower for x in SENSITIVE_NAMES)
                        )
                        else "USER_OR_EXTERNAL_INPUT"
                    )

                    flows.append(
                        {
                            "source": source_name,
                            "classification": classification,
                            "sink": sink,
                            "evidence": {
                                "file": _relative(path, project),
                                "line": node.lineno,
                                "detection": (
                                    "Data-like value passed to observable sink"
                                ),
                            },
                        }
                    )

    flows.sort(
        key=lambda x: (
            x["evidence"]["file"],
            x["evidence"]["line"],
            x["source"],
            x["sink"],
        )
    )
    return flows


def build_risk_register(findings):
    risks = []

    for finding in findings:
        control = CONTROL_MAP.get(finding.rule_id)

        if not control:
            continue

        risks.append(
            {
                "risk_id": "RISK-" + finding.rule_id,
                "rule_id": finding.rule_id,
                "name": finding.name,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "status": "OPEN",
                "control_id": control["control_id"],
                "control": control["control"],
                "domain": control["domain"],
                "evidence": finding.evidence.__dict__.copy(),
            }
        )

    risks.sort(
        key=lambda x: (
            x["severity"],
            x["rule_id"],
            x["evidence"]["file"],
            x["evidence"]["line"],
        )
    )
    return risks


def build_governance_findings(findings):
    governance = []

    for finding in findings:
        control = CONTROL_MAP.get(finding.rule_id)

        if not control:
            continue

        severity = finding.severity
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = "LOW"

        governance.append(
            Finding(
                rule_id="AEGIS-GOV-" + finding.rule_id,
                name="Governance control requires review: " + finding.name,
                category="Governance",
                severity=severity,
                confidence=finding.confidence,
                description=(
                    control["control"]
                    + " Static evidence is inherited from "
                    + finding.rule_id
                    + "."
                ),
                evidence=Evidence(
                    file=finding.evidence.file,
                    line=finding.evidence.line,
                    detection=(
                        "Governance mapping from "
                        + finding.rule_id
                        + ": "
                        + finding.evidence.detection
                    ),
                ),
                remediation=(
                    "Review control "
                    + control["control_id"]
                    + " and remediate the underlying evidence-backed finding."
                ),
            )
        )

    governance.sort(
        key=lambda x: (
            x.rule_id,
            x.evidence.file,
            x.evidence.line,
            x.name,
        )
    )
    return governance


def analyze(project, findings):
    project = Path(project).resolve()

    systems = discover_ai_systems(project)
    data_map = build_data_map(project)
    risks = build_risk_register(findings)
    governance_findings = build_governance_findings(findings)

    controls = []
    seen = set()

    for risk in risks:
        key = risk["control_id"]
        if key in seen:
            continue
        seen.add(key)
        controls.append(
            {
                "control_id": risk["control_id"],
                "control": risk["control"],
                "domain": risk["domain"],
                "linked_rule_ids": [
                    x["rule_id"]
                    for x in risks
                    if x["control_id"] == key
                ],
                "status": "REQUIRES_REVIEW",
            }
        )

    controls.sort(key=lambda x: x["control_id"])

    return {
        "version": "phase5",
        "ai_system_register": systems,
        "data_map": data_map,
        "risk_register": risks,
        "control_mapping": controls,
        "governance_findings": governance_findings,
    }
