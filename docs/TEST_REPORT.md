# Validation report

Validation performed in the creation environment on 2026-09-26 (UTC).

- Linux C++11 release build: passed with `-Wall -Wextra -Wpedantic -pthread` and no compiler diagnostics.
- Unit checks: passed for failure threshold, SUSPECT/ALERT/SLOW/UP states, recovery reset, successful-only latency statistics, CSV escaping/formula protection, invalid IP/port/field count, and duplicate detection.
- Loopback integration: passed for two failed TCP checks followed by a recovered listening service. Observed states SUSPECT, ALERT, UP, UP; three events; four checks; two successes; 50% successful-check rate.
- Daily logs and per-session report fields: verified by parsing actual generated CSV files.
- CLI rejection: invalid action combinations and unknown options rejected.
- Configuration: invalid port and empty target list rejected for monitoring.
- Interactive configuration: add and remove persisted correctly.
- POSIX Ctrl+C/SIGINT: clean shutdown produced report location and successful exit.

Not directly tested: Windows compilation/runtime, Dev-C++ project import, Windows console control events, real LAN/router endpoints, firewall-induced timeouts, high-load resource exhaustion, or long-duration soak behavior. The package does not include a Windows executable. Source implements a Winsock path and supplies Windows build instructions for local validation.

The loopback tests do not require Internet access or a third-party target. The integration suite uses temporary directories and removes its generated data. No production devices were contacted.
