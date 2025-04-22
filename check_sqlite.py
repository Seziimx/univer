import sqlite3

try:
    sqlite3_version = sqlite3.sqlite_version
    print(f"SQLite is available. Version: {sqlite3_version}")
except Exception as e:
    print(f"SQLite is not available. Error: {e}")
