# mcp_vuln_scan
Python 기반 MCP서버 취약점 스캔 프로젝트 
- Git 저장소 목록을 일괄 클론하고, 각 저장소에서 MCP 관련 취약 패턴 사용을 스캔하는 도구입니다.


## 주요 기능
- **저장소 일괄 Clone**  
  `repos.txt`에 나열된 Git URL을 읽어 `cloned_repos/` 폴더에 차례로 클론합니다.  
- **취약점 패턴 스캔**  
  클론된 각 저장소 내에서 “크리티컬” 및 “논크리티컬” 정규식 패턴을 찾아 리포트합니다.
  



## 저장소 구조
````

mcp_vuln_scan/
├── cloned_repos.py      # repos.txt의 URL을 읽어 저장소를 클론하는 스크립트
├── scan_mcp.py          # cloned_repos/ 아래 모든 저장소의 Python파일을 스캔하여 취약 패턴 검색
├── repos.txt            # 한 줄에 하나씩 Git 저장소 URL을 입력
└── cloned_repos/        # (자동 생성) 클론된 저장소들이 위치

````


## 요구사항

- Python 
- Git CLI

## 사용 방법

1. **저장소 목록 준비**
   `repos.txt` 파일에 클론할 Git URL을 한 줄에 하나씩 작성합니다.

   ```text
   https://github.com/example/project-one.git
   https://gitlab.com/another/project-two.git
   ```

2. **저장소 클론**

   ```bash
   python3 cloned_repos.py
   ```

   `cloned_repos/` 디렉터리가 생성되며, 각 URL이 서브폴더로 클론됩니다.

3. **취약점 스캔 실행**

   ```bash
   python3 scan_mcp.py
   ```

   * `cloned_repos/` 내 모든 저장소를 순회하며 정규식 패턴 매치를 검사
   * 카테고리별 매치 개수 요약 및 파일·라인별 상세 결과 출력

   결과를 파일로 저장하려면:

   ```bash
   python3 scan_mcp.py | tee vuln_report.txt
   ```



## 점검 패턴

주요 유형의 **위험 취약점**과, 보조적으로 모니터링하는 **비치명적 패턴**, 그리고 **네트워크 노출** 가능성까지 총 3가지 로 분류하여 검사합니다.

### 1. Critical Patterns  
- **SSRF (Server-Side Request Forgery)**  
  - `requests.get()` 혹은 `urllib.request.urlopen()` 등 외부 URL을 직접 호출하는 코드 탐지  
- **RCE (Remote Code Execution)**  
  - `eval()`, `exec()`, `os.system()`, `subprocess.Popen(shell=True)` 등 코드 실행 함수 사용 패턴  
- **SQL Injection**  
  - `cursor.execute(f"…{param}…")`, `.format()` 혹은 문자열 덧셈으로 쿼리를 조합하는 경우  
  - ORM 사용 시 `session.execute("SELECT …")` 또는 `.raw("SELECT …")` 
- **Pickle RCE**  
  - `pickle.loads()`, `marshal.load()`, `dill.loads()` 등 직렬화 포맷 역직렬화 구문  
- **CSV Injection**  
  - 스프레드시트 계산식을 직접 삽입할 여지가 있는 `=SUM(`, `=cmd|` 등으로 시작하는 셀 값

### 2. Non-Critical Patterns  
- **타임아웃 지정 요청**  
  - `requests(..., timeout=…)` 혹은 `httpx(..., timeout=…)`  
- **로컬 파일 접근**  
  - 상대 경로(`../`), 절대 경로(`/…`)를 직접 `open(...)` 하는 경우  
- **임시파일/압축 해제**  
  - `tempfile.*`, `zipfile.extractall()`, `tarfile.extract()` 등 잠재적 파일 시스템 리스크  
- **동적 코드/모듈 로딩**  
  - `compile()`, `__import__()`, `importlib.import_module()`  
- **정규식 과부하 위험**  
  - `re.match()`, `re.search()`, `re.findall()`

### 3. Network Exposure  
- **0.0.0.0 바인드**  
  - `app.run(host="0.0.0.0")`, `uvicorn.run(..., host="0.0.0.0")`, `socket.bind(("0.0.0.0", …))`  
- **FastAPI/Flask 엔드포인트**  
  - `@app.get(...)`, `@app.post(...)`, `FastAPI(...)`, 도구 자체의 외부 노출 지점  
- **커맨드라인 호스트·포트 인자**  
  - `--host`, `--port`, `--sse` 등 실행 시 외부 접근을 의도하는 옵션


## 출력 예시

* **콘솔 요약**

  ```
  [!] 전체 점검한 저장소 수: 39
  [!] CRITICAL 패턴 발견 저장소 수: 13
  [!] EXPOSURE 패턴 발견 저장소 수: 39

  취약점가능 패턴 사용 건수:
  - CRITICAL (SSRF): 168건
  - CRITICAL (CSVInjection): 10건
  ```
* **상세 리포트**

  ```
  [REPO] project repo
    old\download_sam2_checkpoint.py :: [SSRF] Line 58: response = requests.get(url, stream=True)
    src\ai\venice_api.py :: [SSRF] Line 190: response = requests.get(image_url, stream=True)
  ```

---
