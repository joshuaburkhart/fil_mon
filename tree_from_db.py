#!/usr/bin/env python3
import sys
import sqlite3

DB_FILE = sys.argv[1] if len(sys.argv) > 1 else "file_monitor.db"

def build_tree_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Query distinct files logged and group the processes that touched them
    cursor.execute("""
        SELECT filepath, GROUP_CONCAT(DISTINCT comm || '(PID:' || pid || ')')
        FROM file_events
        GROUP BY filepath;
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print(f"No file events recorded in {DB_FILE}.")
        return

    # Construct nested path dictionary
    root = {}
    for path, procs in rows:
        parts = [p for p in path.split('/') if p]
        curr = root
        for part in parts[:-1]:
            curr = curr.setdefault(part, {})
        filename = f"/{parts[-1]}" if parts else path
        curr[f"{filename}  <-- [{procs}]"] = None

    lines = [f"=== FILE ACCESS TREE ({DB_FILE}) ===", "/"]

    def _render(node, prefix=""):
        items = list(node.items())
        for i, (key, val) in enumerate(items):
            is_last = (i == len(items) - 1)
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{key}")
            if isinstance(val, dict) and val:
                child_prefix = prefix + ("    " if is_last else "│   ")
                _render(val, child_prefix)

    _render(root)
    print("\n".join(lines))

if __name__ == "__main__":
    build_tree_from_db()
