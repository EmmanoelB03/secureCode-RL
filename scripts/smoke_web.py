"""Local HTTP integration check. Starts and cleans up only its own servers."""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    servers = []
    with tempfile.TemporaryDirectory(prefix='securecode-smoke-') as folder:
        log = Path(folder) / 'servers.log'
        with log.open('w+') as output:
            try:
                servers.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', 'backend.app.main:app',
                    '--host', '127.0.0.1', '--port', '18765'], cwd=ROOT, stdout=output, stderr=output))
                env = {**os.environ, 'HOST':'127.0.0.1', 'PORT':'18766',
                       'ORIGIN':'http://127.0.0.1:18766', 'BACKEND_URL':'http://127.0.0.1:18765'}
                servers.append(subprocess.Popen(['node','build'], cwd=ROOT/'frontend', env=env,
                                                stdout=output, stderr=output))
                base = 'http://127.0.0.1:18766'
                for _ in range(60):
                    if any(p.poll() is not None for p in servers):
                        raise RuntimeError(log.read_text())
                    try:
                        with urllib.request.urlopen(base+'/api/v1/health', timeout=1) as response:
                            assert json.load(response)['status'] == 'ok'
                        break
                    except (OSError, urllib.error.URLError):
                        time.sleep(.25)
                else:
                    raise RuntimeError('Servers did not become ready: '+log.read_text())
                for path in ('/', '/dashboard', '/api/v1/model/metrics', '/api/v1/experiments'):
                    with urllib.request.urlopen(base+path) as response:
                        assert response.status == 200
                        print('HTTP 200', path)
                code = (ROOT / 'frontend/static/example.py').read_text()
                for endpoint in ('analyze', 'repair'):
                    req = urllib.request.Request(base+'/api/v1/'+endpoint,
                        data=json.dumps({'code':code}).encode(), headers={'Content-Type':'application/json'})
                    with urllib.request.urlopen(req) as response:
                        result = json.load(response)
                        assert result['alerts'] if endpoint == 'analyze' else result['status'] == 'validated'
                        print('POST', endpoint, 'verified')
                if '--browser' in sys.argv:
                    browser = subprocess.run(['google-chrome', '--headless=new', '--disable-gpu',
                        '--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage',
                        f'--user-data-dir={folder}/chrome', '--virtual-time-budget=8000',
                        '--dump-dom', base+'/dashboard'], capture_output=True, text=True, timeout=30)
                    if browser.returncode != 0 or 'Validação cruzada por grupos' not in browser.stdout or '454 exemplos' not in browser.stdout:
                        raise RuntimeError('Browser check failed: '+browser.stderr[-2000:])
                    print('Browser dashboard hydration verified')
            finally:
                for process in servers:
                    process.terminate()
                for process in servers:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == '__main__':
    main()
