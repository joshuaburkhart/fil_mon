#!/usr/bin/env python3
import os
import sys
import time
import sqlite3
import subprocess
from collections import defaultdict

DB_FILE = "file_monitor.db"

def init_db():
    """Initialize an optimized SQLite database with filepath indexing."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filepath TEXT NOT NULL,
            pid INTEGER NOT NULL,
            comm TEXT NOT NULL,
            action TEXT NOT NULL,
            fd INTEGER,
            timestamp DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_filepath ON file_events(filepath);")
    conn.commit()
    return conn

def render_ascii_tree(active_files):
    """Generates an ASCII tree structure of currently open files."""
    if not active_files:
        return "=== LIVE OPEN FILES TREE ===\n\n  (No active non-system files open)"

    root = {}
    for path, procs in active_files.items():
        parts = [p for p in path.split('/') if p]
        curr = root
        for part in parts[:-1]:
            curr = curr.setdefault(part, {})
        
        proc_str = ", ".join(f"{comm}(PID:{pid})" for pid, comm in procs)
        filename = f"/{parts[-1]}" if parts else path
        curr[f"{filename}  <-- [{proc_str}]"] = None

    lines = ["=== LIVE OPEN FILES TREE ===", "/"]
    
    def _build_tree(node, prefix=""):
        items = list(node.items())
        for i, (key, val) in enumerate(items):
            is_last = (i == len(items) - 1)
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{key}")
            if isinstance(val, dict) and val:
                child_prefix = prefix + ("    " if is_last else "│   ")
                _build_tree(val, child_prefix)

    _build_tree(root)
    return "\n".join(lines)

def main():
    if os.geteuid() != 0:
        print("Error: Root privileges required. Run with 'sudo python3 live_file_monitor.py'")
        sys.exit(1)

    conn = init_db()
    cursor = conn.cursor()

    # Zero BPF map overhead: emit enter/exit pairs directly to stdout
    bpftrace_code = '''
    tracepoint:syscalls:sys_enter_openat
    {
        printf("ENTER_OPEN|%d|%d|%s|%s\\n", tid, pid, comm, str(args->filename));
    }

    tracepoint:syscalls:sys_exit_openat
    {
        printf("EXIT_OPEN|%d|%d\\n", tid, args->ret);
    }

    tracepoint:syscalls:sys_enter_close
    {
        printf("CLOSE|%d|%s|%d\\n", pid, comm, args->fd);
    }

    tracepoint:syscalls:sys_enter_exit_group
    {
        printf("EXIT|%d|%s\\n", pid, comm);
    }
    '''

    print("Initializing eBPF probes...")
    
    env = os.environ.copy()
    env["BPFTRACE_STRLEN"] = "200"

    cmd = ["stdbuf", "-oL", "bpftrace", "-e", bpftrace_code]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        env=env
    )

    pending_opens = {} # tid -> (pid, comm, path)
    open_fds = {}      # (pid, fd) -> path
    active_tree = defaultdict(set)
    last_draw = 0

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue

            line = line.strip()
            if not line or '|' not in line:
                continue

            parts = line.split('|')
            event_type = parts[0]

            if event_type == "ENTER_OPEN" and len(parts) >= 5:
                tid, pid, comm, path = int(parts[1]), int(parts[2]), parts[3], parts[4]
                pending_opens[tid] = (pid, comm, path)

            elif event_type == "EXIT_OPEN" and len(parts) >= 3:
                tid, ret = int(parts[1]), int(parts[2])
                if tid in pending_opens:
                    pid, comm, path = pending_opens.pop(tid)
                    
                    # Check successful file descriptor creation
                    if ret >= 0 and path:
                        if path.startswith(("/proc", "/sys", "/dev", "/etc", "/lib", "/usr")):
                            continue

                        fd = ret
                        open_fds[(pid, fd)] = path
                        active_tree[path].add((pid, comm))

                        cursor.execute(
                            "INSERT INTO file_events (filepath, pid, comm, action, fd) VALUES (?, ?, ?, ?, ?)",
                            (path, pid, comm, "OPEN", fd)
                        )
                        conn.commit()

            elif event_type == "CLOSE" and len(parts) >= 4:
                pid, comm, fd = int(parts[1]), parts[2], int(parts[3])
                if (pid, fd) in open_fds:
                    path = open_fds.pop((pid, fd))
                    active_tree[path].discard((pid, comm))
                    if not active_tree[path]:
                        del active_tree[path]

                    cursor.execute(
                        "INSERT INTO file_events (filepath, pid, comm, action, fd) VALUES (?, ?, ?, ?, ?)",
                        (path, pid, comm, "CLOSE", fd)
                    )
                    conn.commit()

            elif event_type == "EXIT" and len(parts) >= 3:
                pid, comm = int(parts[1]), parts[2]
                to_remove = [key for key in open_fds if key[0] == pid]
                for key in to_remove:
                    path = open_fds.pop(key)
                    active_tree[path].discard((pid, comm))
                    if not active_tree[path]:
                        del active_tree[path]

            now = time.time()
            if now - last_draw > 0.1:
                os.system("clear")
                print(render_ascii_tree(active_tree))
                print(f"\n[Logging to SQLite: {DB_FILE}] Press Ctrl+C to stop.")
                last_draw = now

    except KeyboardInterrupt:
        print("\nStopping monitor...")
    finally:
        proc.terminate()
        conn.close()

if __name__ == "__main__":
    main()
