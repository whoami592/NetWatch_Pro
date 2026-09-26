# NetWatch Pro 1.0

**Coded by Cyber Security Engineer Mr Sabaz Ali Khan**

A terminal-based C++11 TCP service monitor for Windows/Dev-C++ with a portable Linux build. Monitor a curated list of your services, watch connection times, detect repeated failures, and retain CSV evidence.

## Included features

- Interactive menu: list, add, remove, check once, continuously monitor, or run a fixed number of cycles.
- Up to 64 named IPv4/TCP endpoints with independent timeout, latency threshold and failure threshold.
- Bounded concurrency: four worker threads by default, configurable from one to sixteen.
- Nonblocking TCP connection checks with a timeout. No shell commands or credentials are used.
- `UP`, `SLOW`, `SUSPECT` and `ALERT` states, recovery events and optional terminal bells.
- Connection timing, successful-check percentage, consecutive failure count, and session minimum/average/maximum connection times.
- Append-only daily check history and state-change event files; a session report refreshed after each cycle.
- Configuration validation, duplicate detection, atomic configuration/report replacement, CSV formula protection, and checked file writes.
- Included Dev-C++ project, Windows build/run scripts, Linux build script, optional local demo, and tests.

## What the measurements mean

A successful check means that the configured **TCP port accepted a connection**. It does not verify HTTP response status, TLS certificates, login, database health, or the entire device.

`ALERT` means consecutive TCP checks failed. A firewall, closed port or stopped service can cause this while the computer is still online. `REFUSED`, `TIMEOUT`, `UNREACHABLE`, and socket errors are recorded separately.

`connect_ms` measures a successful TCP connection attempt using a monotonic clock. It is not an ICMP ping measurement. Failed attempt durations are retained in the daily history but excluded from successful-connection latency averages.

`success_percent` is successful checks / total checks in the current session. **It is not network packet loss or time-weighted uptime.** The application does not capture traffic or send ICMP probes.

This edition uses dependency-free CSV history, not SQLite. It supports numeric IPv4 addresses and TCP ports; it does not perform DNS resolution, IPv6 checks, automatic discovery, SNMP or bandwidth tests.

## Windows: build in Dev-C++

1. Extract the entire ZIP into a writable folder, for example `E:\NetWatch_Pro`.
2. Open `NetWatchPro.dev` in Dev-C++.
3. Use a MinGW-w64 C++ compiler with C++11 and `std::thread` support. For GCC/MinGW distributions with multiple thread models, use a compiler build that supports `std::thread` (commonly the POSIX thread model).
4. Check project compiler parameters contain:
   ```text
   -std=c++11 -O2 -Wall -Wextra -pthread
   ```
5. Check linker parameters contain:
   ```text
   -lws2_32 -pthread
   ```
6. Compile the project. Run the generated `NetWatchPro.exe` from the project directory, or double-click `run_windows.bat`.

If your Dev-C++ version does not import the `.dev` parameters correctly, create a **C++ Console Application**, add `main.cpp`, and enter the parameters above manually. The batch build is an independent fallback.

### Build using the included batch file

If `g++` is on PATH, double-click `build_windows.bat`. Otherwise open Command Prompt in the extracted folder and pass your actual compiler path:

```bat
build_windows.bat "C:\path\to\MinGW64\bin\g++.exe"
```

The equivalent command is:

```bat
g++ -std=c++11 -O2 -Wall -Wextra -pthread main.cpp -o NetWatchPro.exe -lws2_32
```

Keep the compiler's required runtime DLLs available on PATH if your compiler produces a dynamically linked executable. Run through the same compiler environment or copy the appropriate redistributable runtime DLLs from your own compiler installation alongside the executable. Do not download random DLLs.

The package includes source code, **not a prebuilt Windows executable**. The Linux build and local network behavior were tested in the creation environment; a Windows compiler/runtime and Dev-C++ UI were unavailable for direct validation.

## First run: local demo

The default target is `127.0.0.1:8765`, on your own computer. It will fail until a service listens there. This is expected, not an installation error.

If Python 3 is installed, open a terminal in the extracted folder:

```bat
python demo_server.py
```

Keep it running. Open `run_windows.bat`, choose **4. Check once**, and expect `UP` with `CONNECTED`. Select **5. Monitor continuously**. Stop the demo server using Ctrl+C in its terminal; after three failed checks, NetWatch enters `ALERT`. Start the demo server again to see recovery.

Python is optional and is only used for the demo/tests. The C++ monitor itself does not require Python.

## Add your router or server

Use menu option **2**, or edit `targets.conf` while monitoring is stopped. Format:

```text
name|numeric_IPv4|TCP_port|timeout_ms|slow_threshold_ms|consecutive_failures
```

Example, **only if your router's web interface actually listens on this address and port**:

```text
Router Web|192.168.1.1|80|1500|200|3
```

A TLS-enabled web service may use port 443; SSH commonly uses 22. Configure the actual enabled service. This tool sends no application request or password, and an open port alone does not prove application health.

Names: 1-32 printable ASCII characters without `|`. IP: unicast numeric IPv4. Port: 1-65535. Timeout: 100-10000 ms. Slow threshold: 1-10000 ms. Failure threshold: 1-20. Maximum 64 unique names/endpoints.

Blank lines and lines beginning with `#` are ignored. Inline comments are not supported. Invalid entries stop loading with the line number so monitoring cannot silently omit a broken target. Configuration is reloaded between menu actions, not during an active monitoring session.

## CLI usage

```bat
NetWatchPro.exe --help
NetWatchPro.exe --list
NetWatchPro.exe --once
NetWatchPro.exe --watch --interval 5 --workers 4 --bell
NetWatchPro.exe --cycles 12 --interval 5
NetWatchPro.exe --watch --config "E:\Monitoring\targets.conf" --out "E:\Monitoring\results"
```

| Option | Meaning |
|---|---|
| No action | Interactive menu |
| `--once` | One monitoring cycle |
| `--watch` | Continuous monitoring |
| `--cycles N` | N cycles; 0 means continuous |
| `--list` | Show validated target configuration |
| `--config PATH` | Configuration path; default `targets.conf` |
| `--out PATH` | Output folder; default `output` |
| `--interval N` | Wait 1-3600 seconds **after** each cycle; default 5 |
| `--workers N` | Concurrent checks, 1-16; default 4 |
| `--bell` | Audible terminal bell on entering ALERT or SLOW, if terminal supports it |

Use one action flag per invocation. Relative paths are relative to the process working directory. The output folder can be created by the program, but its parent must already exist. Do not run two processes against the same configuration/output folder; use separate folders for separate instances.

Ctrl+C requests a clean stop. An in-flight cycle finishes its checks and writes its report before exit/return to the menu. With many targets, this can take approximately `ceil(targets/workers) * timeout`, plus scheduling and disk time. Samples are taken concurrently in batches; logged timestamps identify the completed cycle, not exact individual start times.

Exit status 0 means the program completed successfully, including a run that found failed services. Exit status 1 means invalid arguments, configuration or an operational error. Use CSV state/result fields for monitoring outcomes.

## Reports and history

```text
output/
  logs/
    checks_YYYY-MM-DD.csv
    events_YYYY-MM-DD.csv
  reports/
    session_TIMESTAMP_UNIQUEID.csv
```

Open these files in Excel, LibreOffice, or a text editor. Timestamps and daily filenames use the computer's local timezone. A session ID joins check and event records to the session summary. Session statistics start fresh for each monitoring run; historical CSVs remain on disk. The program does not aggregate historical sessions automatically.

The session report is replaced after each cycle. Viewing it in software that locks the file may block the next write; open a copy instead. Daily history grows without an automatic retention limit, so archive or remove older logs as needed. Reports can expose internal IP addresses and names; keep them in an appropriate local folder.

### State transitions

- First failed check: `SUSPECT`, unless failure threshold is 1.
- Consecutive failures reach the configured threshold: `ALERT`.
- Successful connection exceeding the latency threshold: `SLOW`.
- Successful connection at or below the latency threshold: `UP`.
- Any success resets the consecutive failure count.
- Every state change is recorded, including the initial `UNKNOWN` transition.

A single successful check recovers immediately; there is no recovery debounce. Console events and optional local bells are provided; there are no email, SMS, desktop or webhook notifications.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `g++ is not recognized` | Supply the full compiler path to the batch file or build inside Dev-C++. |
| `std::thread` missing / compilation fails | Enable C++11 and use a MinGW-w64 compiler with working standard thread support; keep `-pthread` in compiler/linker parameters. |
| Undefined references to `WSAStartup`, `connect`, `select` | Add `-lws2_32` to linker parameters, after source/object inputs. |
| Cannot open `targets.conf` | Run from the extracted project directory or pass an absolute `--config` path. |
| Default local demo fails | Start `demo_server.py`, or replace the default target with a real service. |
| `REFUSED` | The host/network actively rejected the connection; check listening port and service. |
| `TIMEOUT` | Connection did not complete before the timeout; inspect routing, firewall, connectivity, and configured timeout. |
| `UNREACHABLE` | Check the network route/interface and target address. |
| Cannot replace session report | Close the report in Excel or other software that locks it. |
| Slow monitoring rounds | Reduce target timeout/count or increase workers moderately; interval begins after the entire round. |

## Linux build

```bash
bash build_linux.sh
./NetWatchPro --once
```

## Verification

Python 3 and a compiler are only needed for development tests:

```bash
g++ -std=c++11 -Wall -Wextra -Wpedantic -pthread tests/unit.cpp -o netwatch_unit
./netwatch_unit
python3 tests/integration.py ./NetWatchPro
```

For Windows unit tests append `-lws2_32`, use `.exe` output names, and run Python with the appropriate executable path. The POSIX signal test is skipped on Windows. See `docs/TEST_REPORT.md` for actual validation scope.

## Project layout

- `main.cpp`: portable socket layer, strict config validation, probe worker pool, state engine, CSV persistence and interactive/CLI interface.
- `NetWatchPro.dev`: Dev-C++ console project.
- `targets.conf`: editable target list with a local demo endpoint.
- `build_windows.bat`, `run_windows.bat`, `build_linux.sh`: build/run helpers.
- `demo_server.py`: optional loopback-only demo listener.
- `tests/`: deterministic state/validation tests and local integration checks.
- `START_HERE.txt`: short Roman Urdu setup guide.

Use only endpoints you own or are authorized to monitor. This application connects only to explicitly configured TCP services; it is not a discovery scanner.
