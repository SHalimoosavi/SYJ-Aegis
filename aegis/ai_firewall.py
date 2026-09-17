import ast
import re
from pathlib import Path

from .agentguard import _qualified_name
from .models import Evidence, Finding
from .secrets import RULES, _is_placeholder

LLM_CALL_NAMES = {
    "openai.ChatCompletion.create",
    "openai.Completion.create",
    "client.chat.completions.create",
    "client.completions.create",
    "client.responses.create",
    "client.beta.chat.completions.parse",
    "anthropic.messages.create",
    "llm.invoke",
    "llm.predict",
    "model.generate_content",
    "generate_content",
    "chat.completions.create",
    "responses.create",
}
LLM_METHOD_SUFFIXES = (".chat.completions.create", ".completions.create", ".responses.create", ".messages.create")
LLM_PROMPT_KEYS = {"prompt", "system", "instruction", "instructions", "input", "messages", "content"}
NETWORK_PREFIXES = ("urllib.request.", "http.client.")
NETWORK_NAMES = {"socket.socket", "socket.create_connection", "os.system", "os.popen"}
PII_NAME_RE = re.compile(r"(?i)^(?:email|email_address|phone|phone_number|mobile|mobile_number|ssn|social_security|customer_id|client_id|user_id|address|postal_code|zip_code)$|(?:email|phone|ssn|customer_id|client_id|user_id)")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d .()\-]{7,}\d)(?!\d)")
VECTOR_IMPORTS = {
    "chromadb", "pinecone", "weaviate", "qdrant", "faiss", "pgvector", "milvus"
}
INGEST_NAMES = {"ingest", "load_documents", "add_documents", "upsert", "add_texts"}
RETRIEVAL_NAMES = {"similarity_search", "query", "retrieve", "get_relevant_documents"}
AUTH_TOKENS = ("auth", "tenant", "permission", "access", "acl", "filter", "user_id", "customer_id", "org_id", "organization_id", "role")
DANGEROUS_SIMPLE = {"eval", "exec"}
DANGEROUS_QUALIFIED = {"os.system", "os.popen"}


def _call_name(node):
    return _qualified_name(node.func) or ""


def _is_llm_call(node):
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node)
    if name in LLM_CALL_NAMES or name.endswith(LLM_METHOD_SUFFIXES):
        return True
    return name in {"invoke", "predict", "generate_content"}


def _is_network_call(node):
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node)
    return name in NETWORK_NAMES or name.startswith(NETWORK_PREFIXES)


def _is_logging_call(node):
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node)
    parts = name.split(".")
    return len(parts) >= 2 and parts[-1] in {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"} and parts[-2] in {"logging", "logger", "log"}


def _contains_name(expr, names):
    return any(isinstance(node, ast.Name) and node.id in names for node in ast.walk(expr))


def _request_origin(expr):
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in {"request", "req"}:
            return node
    return None


def _expr_tainted(expr, parameter_names):
    if isinstance(expr, ast.JoinedStr):
        return any(_expr_tainted(value.value, parameter_names) for value in expr.values if isinstance(value, ast.FormattedValue))
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _expr_tainted(expr.left, parameter_names) or _expr_tainted(expr.right, parameter_names)
    if isinstance(expr, ast.Name):
        return expr.id in parameter_names or PII_NAME_RE.search(expr.id) is not None
    if isinstance(expr, ast.Attribute):
        return _request_origin(expr) is not None
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return any(_expr_tainted(item, parameter_names) for item in expr.elts)
    if isinstance(expr, ast.Dict):
        return any(_expr_tainted(item, parameter_names) for item in expr.values if item is not None)
    return False


def _origin_evidence(expr, root, path, parameter_names, function_node):
    request_node = _request_origin(expr)
    if request_node is not None:
        return {"file": path.relative_to(root).as_posix(), "line": request_node.lineno, "detection": f"request-derived input: {ast.unparse(request_node)}"}
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in parameter_names:
            return {"file": path.relative_to(root).as_posix(), "line": node.lineno, "detection": f"function parameter: {node.id}"}
    for arg in function_node.args.args + function_node.args.kwonlyargs:
        if arg.arg in parameter_names:
            return {"file": path.relative_to(root).as_posix(), "line": arg.lineno, "detection": f"function parameter: {arg.arg}"}
    return None


def _call_arg_expressions(call):
    for keyword in call.keywords:
        if keyword.arg in LLM_PROMPT_KEYS:
            yield keyword.value
    if not call.keywords and call.args:
        yield call.args[0]


def _literal_secret_label(value):
    for rule_id, label, pattern in RULES:
        match = pattern.search(value)
        if match and (not match.lastindex or not _is_placeholder(match.group(1))):
            return rule_id, label
    return None


def _finding(rule_id, name, category, severity, confidence, description, path, root, node, detection, remediation):
    return Finding(rule_id, name, category, severity, confidence, description, Evidence(path.relative_to(root).as_posix(), node.lineno, detection), remediation)


def _function_nodes(tree):
    return [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]


def prompt_security_findings(tree, path, root):
    findings = []
    for function in _function_nodes(tree):
        parameter_names = {arg.arg for arg in function.args.args + function.args.kwonlyargs}
        tainted_names = {}
        for candidate in ast.walk(function):
            if isinstance(candidate, ast.Assign) and isinstance(candidate.value, (ast.JoinedStr, ast.BinOp, ast.Attribute, ast.Name, ast.List, ast.Tuple, ast.Dict)):
                if _expr_tainted(candidate.value, parameter_names):
                    origin = _origin_evidence(candidate.value, root, path, parameter_names, function)
                    if origin:
                        for target in candidate.targets:
                            if isinstance(target, ast.Name):
                                tainted_names[target.id] = origin
        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                targets = [t for t in node.targets if isinstance(t, ast.Name)]
                if not targets or not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                    continue
                for target in targets:
                    if not re.search(r"(?i)(prompt|instruction|system)", target.id):
                        continue
                    hit = _literal_secret_label(node.value.value)
                    if hit:
                        rule_id, label = hit
                        findings.append(_finding(
                            "AEGIS-AI-001", "Hardcoded secret in privileged prompt", "Prompt Security", "HIGH", "MEDIUM",
                            f"A prompt/instruction/system string contains a pattern matching a {label.lower()} secret rule.", path, root, node,
                            f"prompt-like assignment with {rule_id}: {label}",
                            "Remove sensitive authentication material from prompt templates and use secure secret handling outside the prompt.",
                        ))
            if _is_llm_call(node):
                for expr in _call_arg_expressions(node):
                    if not isinstance(expr, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Attribute, ast.List, ast.Tuple, ast.Dict)):
                        continue
                    origin = _origin_evidence(expr, root, path, parameter_names, function)
                    if isinstance(expr, ast.Name) and expr.id in tainted_names:
                        origin = tainted_names[expr.id]
                    elif not _expr_tainted(expr, parameter_names):
                        continue
                    if origin is None:
                        continue
                    findings.append(_finding(
                        "AEGIS-AI-002", "Potential prompt-injection exposure", "Prompt Security", "HIGH", "MEDIUM",
                        f"An LLM call receives a prompt-like argument built from untrusted input. Origin: {origin['file']}:{origin['line']}; call site: {path.relative_to(root).as_posix()}:{node.lineno}.",
                        path, root, node, "tainted prompt origin + LLM call", "Separate trusted instructions from untrusted content and enforce an explicit trust boundary before constructing privileged prompts.",
                    ))
                    break
    return findings


def _pii_literal(expr):
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        if EMAIL_RE.search(expr.value):
            return "email literal"
        if PHONE_RE.search(expr.value):
            return "phone literal"
    return None


def _pii_origin(expr):
    if isinstance(expr, ast.Name) and PII_NAME_RE.search(expr.id):
        return f"PII-looking variable: {expr.id}"
    literal = _pii_literal(expr)
    if literal:
        return literal
    return None


def data_exposure_findings(tree, path, root):
    findings = []
    for function in _function_nodes(tree):
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            sink = _is_logging_call(node) or _is_llm_call(node) or _is_network_call(node)
            if not sink:
                continue
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                origin = _pii_origin(arg)
                if not origin:
                    continue
                findings.append(_finding(
                    "AEGIS-AI-003", "Potential PII data exposure", "Data Exposure", "HIGH", "LOW" if "literal" in origin else "MEDIUM",
                    f"A PII-like value flows directly into a detected logging, LLM, or network call. Origin: {origin}; sink: {path.relative_to(root).as_posix()}:{node.lineno}.",
                    path, root, node, "PII-like direct argument to sensitive sink", "Review the trust boundary and minimize or redact personal data before logging, sending to a model, or transmitting over a network.",
                ))
                break
    return findings


def _vector_imported(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in VECTOR_IMPORTS:
                    return alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in VECTOR_IMPORTS:
                return node.module.split(".")[0]
    return None


def _looks_authorized(function):
    for node in ast.walk(function):
        if isinstance(node, ast.Name):
            low = node.id.lower()
            if any(token in low for token in AUTH_TOKENS):
                return True
        elif isinstance(node, ast.Attribute):
            low = node.attr.lower()
            if any(token in low for token in AUTH_TOKENS):
                return True
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if any(token in low for token in AUTH_TOKENS):
                return True
    return False


def rag_findings(tree, path, root):
    vector = _vector_imported(tree)
    if not vector:
        return []
    findings = []
    for function in _function_nodes(tree):
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name.split(".")[-1] not in RETRIEVAL_NAMES:
                continue
            # Ingestion names are recognized as part of the RAG source model;
            # authorization review is emitted for retrieval sites.
            _ = any(isinstance(item, ast.Call) and (_call_name(item).split(".")[-1] in INGEST_NAMES) for item in ast.walk(function))
            if _looks_authorized(function):
                continue
            findings.append(_finding(
                "AEGIS-AI-004", "RAG access filtering is unclear", "RAG Security", "HIGH", "LOW",
                "Access filtering: UNCLEAR. Potential risk: Retrieved content may cross authorization boundaries. Severity: HIGH, Status: REVIEW REQUIRED.",
                path, root, node, "retrieval call without authorization/tenant/filter-looking identifier", "Review retrieval authorization and tenant/filter enforcement before retrieved content reaches downstream processing. Status: REVIEW REQUIRED.",
            ))
    return findings


def _llm_result_assignments(function):
    outputs = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and _is_llm_call(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    outputs[target.id] = node
    return outputs


def _expr_contains_output(expr, names):
    return any(isinstance(node, ast.Name) and node.id in names for node in ast.walk(expr))


def _dangerous_sink(node):
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node)
    if name in DANGEROUS_QUALIFIED or name in DANGEROUS_SIMPLE or name.startswith("subprocess."):
        return True
    if name.endswith(".execute") and node.args:
        base = name.rsplit(".", 1)[0].lower()
        if not (base == "cursor" or base.endswith("_cursor") or base.endswith(".cursor")):
            return False
        arg = node.args[0]
        return isinstance(arg, ast.JoinedStr) or (isinstance(arg, ast.Call) and (_call_name(arg) in {"str.format", "format"} or (_call_name(arg) or "").endswith(".format")))
    if name == "open" and len(node.args) >= 2:
        mode = node.args[1]
        return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(flag in mode.value for flag in "wax+")
    return False


def output_sink_findings(tree, path, root):
    findings = []
    for function in _function_nodes(tree):
        outputs = _llm_result_assignments(function)
        if not outputs:
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not _dangerous_sink(node):
                continue
            relevant = any(_expr_contains_output(arg, outputs.keys()) for arg in list(node.args) + [kw.value for kw in node.keywords])
            if not relevant:
                continue
            assignment = next(outputs[name] for name in sorted(outputs) if any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node)))
            findings.append(_finding(
                "AEGIS-AI-017", "Potential unsafe LLM output sink", "Output Security", "CRITICAL", "MEDIUM",
                f"LLM output assigned at {path.relative_to(root).as_posix()}:{assignment.lineno} flows into a dangerous sink at {path.relative_to(root).as_posix()}:{node.lineno}. Review required.",
                path, root, node, "LLM output to dangerous sink", "Treat model output as untrusted data; validate and constrain it before any shell, code, SQL, or filesystem operation.",
            ))
    return findings


def analyze_file(path, root):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return []
    findings = []
    findings.extend(prompt_security_findings(tree, path, root))
    findings.extend(data_exposure_findings(tree, path, root))
    findings.extend(rag_findings(tree, path, root))
    findings.extend(output_sink_findings(tree, path, root))
    return findings
