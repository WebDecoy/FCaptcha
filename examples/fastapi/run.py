"""Local-only launcher: two loopback services and fresh, separate secrets."""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    # Do not inherit production FCaptcha, Redis, or proxy configuration into a demo.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("FCAPTCHA_") and k not in {"REDIS_URL", "TRUSTED_PROXIES"}}
    env.update({
        "FCAPTCHA_SECRET": secrets.token_hex(32),
        "FCAPTCHA_VERIFY_SECRET": secrets.token_hex(32),
        "FCAPTCHA_ALLOWED_HOSTNAMES": "127.0.0.1",
        "FCAPTCHA_SITE_KEYS": "fastapi-demo",
        "TRUSTED_PROXIES": "none",
        "REDIS_URL": "",
        "APP_ORIGIN": "http://127.0.0.1:8790",
        "FCAPTCHA_ORIGIN": "http://127.0.0.1:8791",
    })
    processes = []
    try:
        for module, cwd, port in (("server:app", ROOT / "server-python", 8791),
                                  ("main:app_factory", HERE, 8790)):
            command = [sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1",
                       "--port", str(port), "--no-proxy-headers", "--no-access-log"]
            if port == 8790:
                command.append("--factory")
            processes.append(subprocess.Popen(command, cwd=cwd, env=env))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("A demo service exited; check the errors above")
            try:
                for url in (env["FCAPTCHA_ORIGIN"] + "/fcaptcha.js", env["APP_ORIGIN"] + "/config"):
                    with opener.open(url, timeout=1) as response:
                        response.read(1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Demo services did not become ready")
        print("Open http://127.0.0.1:8790 (use this exact host).", flush=True)
        print("Local demo: no messages are stored or sent. Ctrl+C stops both services.", flush=True)
        while all(p.poll() is None for p in processes):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
