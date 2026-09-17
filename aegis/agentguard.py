import ast
from pathlib import Path

CAPABILITIES = ("read", "write", "execute", "network", "filesystem", "credentials", "destructive")
HIGH_IMPACT = ("execute", "write", "destructive", "network", "credentials")
IGNORED_DIRS = {".git", ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache"}
TOOL_DECORATORS = {"tool", "function_tool", "agent_tool", "register_tool"}
TOOL_REGISTRATIONS = {"register_tool", "add_tool"}


def _simple_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _qualified_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return None


def _is_tool_decorator(node):
    target = node.func if isinstance(node, ast.Call) else node
    name = _simple_name(target)
    qualified = _qualified_name(target) or ""
    return name in TOOL_DECORATORS or qualified.endswith(".tool")


def _evidence(path, root, line, detection):
    return {
        "file": path.relative_to(root).as_posix(),
        "line": int(line),
        "detection": detection,
    }


def _add(found, capability, path, root, node, detection):
    item = _evidence(path, root, getattr(node, "lineno", 1), detection)
    if item not in found[capability]:
        found[capability].append(item)


def _string_modes(call):
    modes = []
    if len(call.args) >= 2:
        value = call.args[1]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            modes.append(value.value)
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            modes.append(keyword.value.value)
    return modes


def classify_permissions(function_node, path, root):
    found = {capability: [] for capability in CAPABILITIES}
    for node in ast.walk(function_node):
        if isinstance(node, ast.Call):
            qualified = _qualified_name(node.func) or ""
            name = _simple_name(node.func) or ""
            if qualified in {"eval", "exec"} or name in {"eval", "exec"}:
                _add(found, "execute", path, root, node, qualified or name)
            if qualified.startswith("subprocess."):
                _add(found, "execute", path, root, node, qualified)
            if qualified in {"os.system", "os.popen"}:
                _add(found, "execute", path, root, node, qualified)
            if qualified in {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree"}:
                _add(found, "destructive", path, root, node, qualified)
                _add(found, "filesystem", path, root, node, qualified)
            if qualified in {"os.rename", "os.replace", "shutil.move"}:
                _add(found, "destructive", path, root, node, qualified)
                _add(found, "filesystem", path, root, node, qualified)
                _add(found, "write", path, root, node, qualified)
            if qualified in {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree"}:
                _add(found, "filesystem", path, root, node, qualified)
                _add(found, "write", path, root, node, qualified)
            if qualified in {"socket.socket", "socket.create_connection"} or qualified.startswith("urllib.request.") or qualified.startswith("http.client."):
                _add(found, "network", path, root, node, qualified)
            if qualified in {"os.getenv", "os.environ.get"}:
                _add(found, "credentials", path, root, node, qualified)
            if name == "open":
                modes = _string_modes(node)
                if modes and any(any(flag in mode for flag in "wax+") for mode in modes):
                    _add(found, "write", path, root, node, "open(write mode)")
                else:
                    _add(found, "read", path, root, node, "open(read/default mode)")
                _add(found, "filesystem", path, root, node, "open")
            if name in {"read_text", "read_bytes"}:
                _add(found, "read", path, root, node, qualified or name)
                _add(found, "filesystem", path, root, node, qualified or name)
            if name in {"write_text", "write_bytes"}:
                _add(found, "write", path, root, node, qualified or name)
                _add(found, "filesystem", path, root, node, qualified or name)
        elif isinstance(node, ast.Name):
            upper = node.id.upper()
            if any(token in upper for token in ("API_KEY", "APIKEY", "ACCESS_TOKEN", "AUTH_TOKEN", "PASSWORD", "SECRET", "PRIVATE_KEY", "CREDENTIAL")):
                _add(found, "credentials", path, root, node, f"credential-looking identifier: {node.id}")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
                _add(found, "credentials", path, root, node, "os.environ")
    for capability in found:
        found[capability].sort(key=lambda item: (item["file"], item["line"], item["detection"]))
    return found


def _function_map(tree):
    return {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _registered_names(tree, functions):
    names = set()
    for function in functions.values():
        if any(_is_tool_decorator(decorator) for decorator in function.decorator_list):
            names.add(function.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _qualified_name(node.func) or ""
        if _simple_name(node.func) in TOOL_REGISTRATIONS:
            for argument in node.args:
                if isinstance(argument, ast.Name) and argument.id in functions:
                    names.add(argument.id)
        for keyword in node.keywords:
            if keyword.arg != "tools" or not isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                continue
            for element in keyword.value.elts:
                if isinstance(element, ast.Name) and element.id in functions:
                    names.add(element.id)
    return names


def discover_tools(project):
    root = Path(project).resolve()
    tools = []
    for path in sorted(root.rglob("*.py"), key=lambda item: item.as_posix()):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            continue
        functions = _function_map(tree)
        for name in sorted(_registered_names(tree, functions)):
            function = functions[name]
            tools.append({
                "name": function.name,
                "source": _evidence(path, root, function.lineno, "agent tool definition"),
                "description": ast.get_docstring(function, clean=False),
                "capabilities": classify_permissions(function, path, root),
            })
    tools.sort(key=lambda item: (item["source"]["file"], item["source"]["line"], item["name"]))
    return tools


def excessive_agency_findings(tools):
    from .models import Evidence, Finding
    findings = []
    for tool in tools:
        active = [capability for capability in HIGH_IMPACT if tool["capabilities"].get(capability)]
        if len(active) < 2:
            continue
        evidence_items = []
        for capability in active:
            evidence_items.extend(tool["capabilities"][capability])
        evidence_items.sort(key=lambda item: (item["file"], item["line"], item["detection"]))
        evidence_summary = ", ".join(
            f"{capability}: {tool['capabilities'][capability][0]['file']}:{tool['capabilities'][capability][0]['line']}"
            for capability in active
        )
        first = evidence_items[0]
        findings.append(Finding(
            "AEGIS-AGENCY-001",
            "Potential excessive tool agency",
            "Excessive Agency",
            "CRITICAL",
            "HIGH",
            f"Tool '{tool['name']}' combines high-impact capabilities: {', '.join(active)}. Evidence: {evidence_summary}.",
            Evidence(first["file"], first["line"], "combined capabilities: " + ", ".join(active)),
            "Restrict the tool to the minimum capabilities required; separate high-impact operations and enforce explicit authorization boundaries.",
        ))
    findings.sort(key=lambda item: (item.rule_id, item.evidence.file, item.evidence.line, item.name))
    return findings
