import os
import subprocess

def clone_repositories(file_path: str, base_dir: str = "./cloned_repos"):
    # 디렉토리 생성
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    # 파일 읽기
    with open(file_path, "r") as f:
        repo_urls = [line.strip() for line in f if line.strip()]

    # 저장소 클론
    for url in repo_urls:
        repo_name = url.rstrip(".git").split("/")[-1]
        target_path = os.path.join(base_dir, repo_name)

        if os.path.exists(target_path):
            print(f"[SKIP] {repo_name} already exists.")
            continue

        print(f"[CLONING] {url} -> {target_path}")
        try:
            subprocess.run(["git", "clone", url, target_path], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to clone {url}: {e}")

if __name__ == "__main__":
    clone_repositories("repos.txt")
