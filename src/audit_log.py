"""Журнал аудита с защитой от подделки (цепочка хешей SHA-256)."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(record):
    payload = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, path="logs/audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self):
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = None
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["hash"]

    def log(self, event, actor, details, severity="INFO"):
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "severity": severity,
            "details": details,
            "prev_hash": self._last_hash,
        }
        record["hash"] = _digest(record)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self._last_hash = record["hash"]
        return record

    def verify(self):
        """Проверка целостности журнала. Возвращает (True, None) или (False, № строки)."""
        prev = GENESIS
        with self.path.open(encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                stored = rec.pop("hash")
                if rec["prev_hash"] != prev or _digest(rec) != stored:
                    return False, n
                prev = stored
        return True, None