# -*- coding: utf-8 -*-
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import os
import re
import ast
from collections import defaultdict

REPOS_DIR = "./cloned_repos_v2"
VALID_EXTENSIONS = {".py"}

# ==== 공격 유형별 정리 ====
CRITICAL_PATTERNS = {
    "SSRF": [r"requests\.get", r"urllib\.request\.urlopen\s*\("],
    "RCE": [r"\beval\s*\(", r"\bexec\s*\(", r"builtins\.exec\s*\(",
            r"os\.system\s*\(", r"subprocess\.(Popen|run|call).*shell\s*=\s*True"],
    "SQLi": [r"cursor\.execute\s*\(\s*f['\"].*\{.+\}.*['\"]\)",
             r"cursor\.execute\s*\(\s*['\"].*\.format\(",
             r"cursor\.execute\s*\(\s*['\"].*%.*['\"].*\)",
             r"cursor\.execute\s*\(\s*['\"].*\+\s*\w+",
             r"session\.execute\s*\(\s*['\"].*SELECT.*['\"]",
             r"\.raw\s*\(\s*\(\s*['\"].*SELECT.*['\"]"],
    "PickleRCE": [r"pickle\.(load|loads)\s*\(", r"marshal\.(load|loads)\s*\(",
                  r"dill\.(load|loads)\s*\(", r"cloudpickle\.(load|loads)\s*\("],
    "CSVInjection": [r"=cmd", r"=SUM\(", r"=cmd\|"],
}

NON_CRITICAL_PATTERNS = [
    r"requests\.(?:get|post|put|head|delete|request)\([^)]*timeout\s*=",
    r"httpx\.(?:get|post|put|delete|request)\([^)]*timeout\s*=",
    r"http\.client\.(?:HTTPConnection|HTTPSConnection)\s*\(",
    r"urllib3\.PoolManager\s*\(",
    r"aiohttp\.ClientSession\s*\(",
    r"open\s*\(\s*['\"]?(/|(\.\./)+)[^,]*\)",
    r"\btempfile\.(mktemp|NamedTemporaryFile|TemporaryDirectory)\s*\(",
    r"\bzipfile\.ZipFile\.(extractall|extract)\s*\(",
    r"\btarfile\.open\s*\(.*\)\.extract(all)?\s*\(",
    r"\bshutil\.rmtree\s*\(",
    r"\bxml\.etree\.(ElementTree|fromstring)\s*\(",
    r"\bxml\.dom\.minidom\.parse\s*\(",
    r"lxml\.etree\.XMLParser\s*\(",
    r"\bcompile\s*\(",
    r"__import__\s*\(",
    r"importlib\.import_module\s*\(",
    r"re\.match\s*\(", r"re\.search\s*\(", r"re\.findall\s*\("
]

NETWORK_EXPOSURE_PATTERNS = {
    "ExternalAccess": [
        r"--host\b", r"--port\b", r"\bsse\b", r"0\.0\.0\.0", r"app\.route",
        r"app\.run\s*\(\s*.*host\s*=\s*['\"]0\.0\.0\.0['\"]",
        r"uvicorn\.run\s*\(\s*.*host\s*=\s*['\"]0\.0\.0\.0['\"]",
        r"socket\.bind\s*\(\s*\(\s*['\"]0\.0\.0\.0['\"]\s*,",
        r"FastMCP\(.+port\s*=\s*\d+",
        r"FastMCP\(.+host\s*=\s*['\"]0\.0\.0\.0['\"]",
        r"app\s*=\s*FastAPI\s*\(",
        r"@app\.get\(", r"@app\.post\("
    ]
}

def is_comment_or_blank(line):
    return not line.strip() or line.strip().startswith("#")

class ExecEvalDetector(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node: ast.Call):
        # eval/exec/compile 직접 호출
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "compile"):
            self.issues.append((node.lineno, ast.unparse(node)))
        # getattr 우회 exec/eval
        elif (isinstance(node.func, ast.Call)
              and isinstance(node.func.func, ast.Name)
              and node.func.func.id == "getattr"
              and len(node.func.args) >= 2):
            attr = node.func.args[1]
            if isinstance(attr, ast.Constant) and attr.value in ("exec", "eval"):
                self.issues.append((node.lineno, f"getattr builtins {attr.value}: {ast.unparse(node)}"))
        # subprocess shell=True
        elif isinstance(node.func, ast.Attribute):
            mod = getattr(node.func.value, 'id', None)
            if mod == 'subprocess' or (isinstance(node.func.value, ast.Attribute)
                                       and getattr(node.func.value.value, 'id', None) == 'subprocess'):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.issues.append((node.lineno, ast.unparse(node)))
        self.generic_visit(node)

def ast_check(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=filepath)
        detector = ExecEvalDetector()
        detector.visit(tree)
        return detector.issues
    except Exception:
        return []

def search_patterns_in_file(filepath):
    critical_hits, non_critical_hits, exposure_hits = [], [], []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            if is_comment_or_blank(line):
                continue
            for category, patterns in CRITICAL_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line):
                        critical_hits.append((category, pat, lineno, line.strip()))
            for pat in NON_CRITICAL_PATTERNS:
                if re.search(pat, line):
                    non_critical_hits.append((pat, lineno, line.strip()))
            for category, patterns in NETWORK_EXPOSURE_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, line):
                        exposure_hits.append((category, pat, lineno, line.strip()))
    return critical_hits, non_critical_hits, exposure_hits

def scan_repository(repo_path):
    findings = {}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d.lower() not in ("test", "tests", ".venv", "examples")]
        for fname in files:
            if os.path.splitext(fname)[1] in VALID_EXTENSIONS:
                full = os.path.join(root, fname)
                crit, noncrit, exposure = search_patterns_in_file(full)
                ast_issues = ast_check(full)
                if crit or noncrit or exposure or ast_issues:
                    findings[full] = (crit, noncrit, exposure, ast_issues)
    return findings

def main():
    if not os.path.isdir(REPOS_DIR):
        print(f"[!] 경로가 없습니다: {REPOS_DIR}")
        return

    # 카운터 초기화
    critical_counter = defaultdict(int)
    noncritical_count = 0
    exposure_counter = defaultdict(int)
    ast_count = 0

    repo_results = {}
    scan_summary = {
        "critical_repos": set(),
        "exposure_repos": set()
    }

    all_repos = [r for r in sorted(os.listdir(REPOS_DIR)) if os.path.isdir(os.path.join(REPOS_DIR, r))]
    total_repo_count = len(all_repos)

    for repo in all_repos:
        repo_path = os.path.join(REPOS_DIR, repo)
        results = scan_repository(repo_path)
        if not results:
            continue

        repo_data = {"critical": [], "noncritical": [], "exposure": [], "ast": []}
        for filepath, (crit, noncrit, exposure, ast_issues) in results.items():
            # critical 카운팅
            for category, pat, ln, code in crit:
                critical_counter[category] += 1
                repo_data["critical"].append((filepath, category, pat, ln, code))
                scan_summary["critical_repos"].add(repo)
            # noncritical 카운팅
            noncritical_count += len(noncrit)
            for pat, ln, code in noncrit:
                repo_data["noncritical"].append((filepath, pat, ln, code))
            # exposure 카운팅
            for category, pat, ln, code in exposure:
                exposure_counter[category] += 1
                repo_data["exposure"].append((filepath, category, pat, ln, code))
                scan_summary["exposure_repos"].add(repo)
            # AST 이슈 카운팅
            ast_count += len(ast_issues)
            for ln, code in ast_issues:
                repo_data["ast"].append((filepath, ln, code))

        repo_results[repo] = repo_data

    # 요약 출력
    print("\n=========== MCP Server 점검 결과 ===========")
    print(f"[!] 전체 점검한 저장소 수: {total_repo_count}")
    print(f"[!] CRITICAL 패턴 발견 저장소 수: {len(scan_summary['critical_repos'])}")
    print(f"[!] EXPOSURE 패턴 발견 저장소 수: {len(scan_summary['exposure_repos'])}\n")

    # 취약점별 카운트
    print(">>> 취약점가능 패턴 사용 건수:")
    for cat, cnt in critical_counter.items():
        print(f"  - CRITICAL ({cat}): {cnt}건")
    print(f"  - LOW (Non-critical): {noncritical_count}건")
    print(f"  - AST issues: {ast_count}건\n")

    # 결과 출력 
    both_repos = scan_summary["critical_repos"] & scan_summary["exposure_repos"]
    print(f"[!] CRITICAL + EXPOSURE 패턴 모두 발견 저장소 수: {len(both_repos)}")
    for repo in sorted(both_repos):
        print(f"  [REPO] {repo}")

    for repo in sorted(scan_summary["critical_repos"]):
        data = repo_results[repo]
        print(f"\n[REPO] {repo}")
        if data["critical"]:
            print("  [CRITICAL]")
            for fp, category, pat, ln, code in data["critical"]:
                rel = os.path.relpath(fp, os.path.join(REPOS_DIR, repo))
                print(f"    {rel} :: [{category}] Line {ln}: {code}")
        if data["exposure"]:
            print("  [EXPOSURE]")
            for fp, category, pat, ln, code in data["exposure"]:
                rel = os.path.relpath(fp, os.path.join(REPOS_DIR, repo))
                print(f"    {rel} :: [{category}] Line {ln}: {code}")
        if data["noncritical"]:
            print("  [LOW]")
            for fp, pat, ln, code in data["noncritical"]:
                rel = os.path.relpath(fp, os.path.join(REPOS_DIR, repo))
                print(f"    {rel} :: Line {ln}: {code}")
        if data["ast"]:
            print("  [AST]")
            for fp, ln, code in data["ast"]:
                rel = os.path.relpath(fp, os.path.join(REPOS_DIR, repo))
                print(f"    {rel} :: AST Line {ln}: {code}")

    for repo in sorted(scan_summary["exposure_repos"] - scan_summary["critical_repos"]):
        data = repo_results[repo]
        print(f"\n[REPO] {repo}")
        if data["exposure"]:
            print("  [EXPOSURE]")
            for fp, category, pat, ln, code in data["exposure"]:
                rel = os.path.relpath(fp, os.path.join(REPOS_DIR, repo))
                print(f"    {rel} :: [{category}] Line {ln}: {code}")
        if data["noncritical"]:
            print("  [LOW]")
            for fp, pat, ln, code in data["noncritical"]:
                rel = os.path.relpath(fp, os.path.join(REPOS_DIR, repo))
                print(f"    {rel} :: Line {ln}: {code}")
        if data["ast"]:
            print("  [AST]")
            for fp, ln, code in data["ast"]:
                rel = os.path.relpath(fp, os.path.join(REPOS_DIR, repo))
                print(f"    {rel} :: AST Line {ln}: {code}")

if __name__ == "__main__":
    main()
