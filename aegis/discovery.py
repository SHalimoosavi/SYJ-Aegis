from pathlib import Path
LANGUAGE_EXTENSIONS={".py":"Python",".js":"JavaScript",".jsx":"JavaScript",".ts":"TypeScript",".tsx":"TypeScript",".java":"Java",".go":"Go",".rs":"Rust"}
IGNORED_DIRS={".git",".hg",".svn",".venv","venv","node_modules","__pycache__",".mypy_cache",".pytest_cache",".tox"}
def iter_project_files(project):
    project=Path(project).resolve()
    for p in sorted(project.rglob("*"),key=lambda x:x.as_posix()):
        if p.is_file() and not any(x in IGNORED_DIRS for x in p.parts): yield p
def discover(project):
    files=list(iter_project_files(project)); langs={}; evidence=[]
    for p in files:
        lang=LANGUAGE_EXTENSIONS.get(p.suffix.lower())
        if lang:
            langs[lang]=langs.get(lang,0)+1
            evidence.append({"type":"language","name":lang,"file":p.relative_to(project).as_posix(),"line":1})
    frameworks=[]
    for p in files:
        if p.name=="requirements.txt":
            text=p.read_text(encoding="utf-8",errors="ignore").lower()
            for needle,name in [("fastapi","FastAPI"),("langchain","LangChain"),("chromadb","Chroma"),("openai","OpenAI")]:
                if needle in text:
                    frameworks.append(name); evidence.append({"type":"framework","name":name,"file":p.relative_to(project).as_posix(),"line":1})
        if p.name=="package.json":
            text=p.read_text(encoding="utf-8",errors="ignore").lower()
            for needle,name in [('"next"',"Next.js"),('"react"',"React")]:
                if needle in text:
                    frameworks.append(name); evidence.append({"type":"framework","name":name,"file":p.relative_to(project).as_posix(),"line":1})
    containers=[]; ci=[]
    for p in files:
        if p.name in {"Dockerfile","docker-compose.yml","docker-compose.yaml"}:
            containers.append("Docker"); evidence.append({"type":"container","name":"Docker","file":p.relative_to(project).as_posix(),"line":1})
        if ".github" in p.parts and "workflows" in p.parts and p.suffix.lower() in {".yml",".yaml"}:
            ci.append("GitHub Actions"); evidence.append({"type":"ci","name":"GitHub Actions","file":p.relative_to(project).as_posix(),"line":1})
    evidence.sort(key=lambda x:(x["type"],x["name"],x["file"],x["line"]))
    return {"languages":[{"name":k,"file_count":langs[k]} for k in sorted(langs)],"frameworks":sorted(set(frameworks)),"containers":sorted(set(containers)),"ci":sorted(set(ci)),"evidence":evidence,"files_scanned":len(files)}
