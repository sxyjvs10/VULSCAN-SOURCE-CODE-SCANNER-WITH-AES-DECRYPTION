import sqlite3
import os
import datetime
from packaging import version as pkg_version

class VulnerabilityDB:
    def __init__(self, db_path="vuln_data.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Table for CVE data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE,
                    software_name TEXT,
                    version_affected TEXT,
                    severity TEXT,
                    description TEXT,
                    published_date TEXT
                )
            ''')
            # Table for metadata (last update)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            conn.commit()

    def add_vulnerability(self, cve_id, software, version, severity, description, published_date):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, software_name, version_affected, severity, description, published_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (cve_id, software, version, severity, description, published_date))
            conn.commit()

    def get_vulnerabilities(self, software_name, version_str=None):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch all potential candidates for this software
            cursor.execute('SELECT * FROM vulnerabilities WHERE software_name LIKE ?', (f'%{software_name}%',))
            candidates = [dict(row) for row in cursor.fetchall()]
            
            if not version_str:
                return candidates

            # Version filtering
            matching_vulns = []
            try:
                detected_ver = pkg_version.parse(version_str)
            except Exception:
                # If detected version is unparseable (e.g., "dev-build"), return all or handle gracefully
                return candidates

            for vuln in candidates:
                affected = vuln['version_affected']
                if not affected or affected == "UNKNOWN":
                    continue
                
                if affected == "all":
                    matching_vulns.append(vuln)
                    continue

                try:
                    if affected.startswith("<="):
                        limit = pkg_version.parse(affected[2:])
                        if detected_ver <= limit:
                            matching_vulns.append(vuln)
                    elif affected.startswith("<"):
                        limit = pkg_version.parse(affected[1:])
                        if detected_ver < limit:
                            matching_vulns.append(vuln)
                    elif affected == version_str:
                         matching_vulns.append(vuln)
                    else:
                        # Basic string match fallback
                        if version_str in affected:
                            matching_vulns.append(vuln)
                except Exception:
                    pass
            
            return matching_vulns

    def set_last_update(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            now = datetime.datetime.now().isoformat()
            cursor.execute('INSERT OR REPLACE INTO metadata (key, value) VALUES ("last_update", ?)', (now,))
            conn.commit()

    def get_last_update(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM metadata WHERE key = "last_update"')
            row = cursor.fetchone()
            return row[0] if row else "Never"
