"""Local-only integration checks. Usage: python tests/integration.py ./NetWatchPro"""
import csv
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading

binary = str(pathlib.Path(sys.argv[1]).resolve())

def rows(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))

def run(*args, **kwargs):
    return subprocess.run([binary, *args], text=True, capture_output=True, timeout=15, **kwargs)

with tempfile.TemporaryDirectory(prefix="netwatch-test-") as td:
    root = pathlib.Path(td)
    conf = root / "targets.conf"
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    conf.write_text(f'Test|127.0.0.1|{port}|300|10000|2\n')
    output = root / "out"
    # Socket is bound but not listening: first two checks must fail.
    proc = subprocess.Popen([binary, "--cycles", "4", "--interval", "1", "--config", str(conf), "--out", str(output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    timer = threading.Timer(15, proc.kill)
    timer.start()
    saw_cycles = 0
    transcript = []
    try:
        for line in proc.stdout:
            transcript.append(line)
            if line.startswith("ALERT means"):
                saw_cycles += 1
                if saw_cycles == 2:
                    server.listen(16)
        assert proc.wait(timeout=5) == 0, proc.stderr.read()
    finally:
        timer.cancel()
        server.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    checks = rows(next((output / "logs").glob("checks_*.csv")))
    events = rows(next((output / "logs").glob("events_*.csv")))
    summary = rows(next((output / "reports").glob("session_*.csv")))[0]
    assert [r['state'] for r in checks] == ['SUSPECT', 'ALERT', 'UP', 'UP'], checks
    assert [r['new_state'] for r in events] == ['SUSPECT', 'ALERT', 'UP'], events
    assert summary['checks'] == '4' and summary['successful_checks'] == '2'
    assert summary['success_percent'] == '50.00', summary
    assert 'Session report:' in ''.join(transcript)
    assert run('--bad').returncode != 0
    assert run('--once', '--watch').returncode != 0
    conf.write_text('Bad|127.0.0.1|70000|300|200|2\n')
    assert run('--once', '--config', str(conf)).returncode != 0
    conf.write_text('')
    assert run('--once', '--config', str(conf)).returncode != 0
    # Exercise durable menu edits and deletion.
    result = run('--config', str(conf), input='2\nMenu service|127.0.0.1|8765|300|200|2\n0\n')
    assert result.returncode == 0 and 'Menu service|' in conf.read_text()
    result = run('--config', str(conf), input='3\n1\n0\n')
    assert result.returncode == 0 and 'Menu service|' not in conf.read_text()
    # SIGINT is directly testable on POSIX; Windows requires console control events.
    if sys.platform != 'win32':
        conf.write_text(f'Test|127.0.0.1|{port}|300|200|2\n')
        proc = subprocess.Popen([binary, '--watch', '--config', str(conf), '--out', str(root/'stop')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        timer = threading.Timer(15, proc.kill)
        timer.start()
        try:
            for line in proc.stdout:
                if line.startswith('ALERT means'):
                    proc.send_signal(signal.SIGINT)
                    break
            stdout, stderr = proc.communicate(timeout=5)
            assert proc.returncode == 0, stderr
            assert 'Session report:' in stdout
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
print('Integration passed: refused service, threshold alert, recovery, metrics, daily logs, reports, invalid configuration, menu persistence and POSIX shutdown.')
