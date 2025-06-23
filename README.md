# mcp_vuln_scan
Python 기반 MCP서버 취약점 스캔 프로젝트 
Git 저장소 목록을 일괄 클론하고, 각 저장소에서 MCP 관련 취약 패턴을 스캔하는 도구입니다.

---

## 주요 기능

- **저장소 일괄 Clone**  
  `repos.txt`에 나열된 Git URL을 읽어 `cloned_repos/` 폴더에 차례로 클론합니다.  
- **취약점 패턴 스캔**  
  클론된 각 저장소 내에서 “크리티컬” 및 “논크리티컬” 정규식 패턴을 찾아 리포트합니다.
  

---

## 저장소 구조
````

mcp\_vuln\_scan/
├── cloned\_repos.py      # repos.txt의 URL을 읽어 저장소를 클론하는 스크립트
├── scan\_mcp.py          # cloned_repos/ 아래 모든 저장소의 Python파일을 스캔하여 취약 패턴 검색
├── repos.txt             # 한 줄에 하나씩 Git 저장소 URL을 입력
└── cloned\_repos/        # (자동 생성) 클론된 저장소들이 위치

````

---

## 요구사항

- Python 3.8 이상
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

---

## 패턴 정의

* **CRITICAL\_PATTERNS**
  - RCE, SSRF, SQLi, Pickle RCE, CSV 인젝션 등 고위험 함수/구문
* **NON\_CRITICAL\_PATTERNS**
  - 타임아웃 지정 HTTP 호출, 임시파일 사용, 일부 XML 파서 등 주의할 패턴


---

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
