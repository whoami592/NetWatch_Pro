"""Optional local-only TCP demo; Python 3. No external packages required."""
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 8765))
    server.listen(32)
    print("NetWatch demo service listening on 127.0.0.1:8765. Ctrl+C stops it.", flush=True)
    try:
        while True:
            connection, _ = server.accept()
            connection.close()
    except KeyboardInterrupt:
        print("Demo service stopped.")
