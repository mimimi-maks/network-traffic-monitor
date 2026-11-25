"""Обнаружение DDoS-атак по числу пакетов в секунду (pps)."""
from datetime import timedelta

import numpy as np
import pandas as pd

COLUMNS = ["timestamp", "source_ip", "destination_ip",
           "protocol", "port", "size_bytes", "department"]


def inject_ddos_attack(df, target_ip="192.168.1.10", pps=400,
                       duration_sec=15, seed=7):
    """Добавляет в данные симулированную DDoS-атаку (HTTP flood) на target_ip
    с множества внешних адресов. Нужна только для демонстрации."""
    rng = np.random.default_rng(seed)
    start = (df["timestamp"].min()
             + (df["timestamp"].max() - df["timestamp"].min()) / 2).floor("s")
    n = pps * duration_sec
    offsets = rng.integers(0, duration_sec, n)

    attack = pd.DataFrame({
        "timestamp": [start + timedelta(seconds=int(o)) for o in offsets],
        "source_ip": [
            f"{rng.integers(1, 223)}.{rng.integers(0, 255)}."
            f"{rng.integers(0, 255)}.{rng.integers(1, 255)}"
            for _ in range(n)
        ],
        "destination_ip": target_ip,
        "protocol": "HTTP",
        "port": 80,
        "size_bytes": rng.integers(40, 120, n),
        "department": "Внешний",
    })
    result = pd.concat([df[COLUMNS], attack], ignore_index=True)
    return result.sort_values("timestamp").reset_index(drop=True)


def detect_ddos(df, pps_threshold=200, min_unique_sources=50):
    """Возвращает список инцидентов DDoS.

    Критерий: на один destination_ip за одну секунду пришло больше
    pps_threshold пакетов И не менее min_unique_sources уникальных источников.
    """
    d = df.copy()
    d["second"] = d["timestamp"].dt.floor("s")
    per_sec = (d.groupby(["destination_ip", "second"])
                 .agg(packets=("source_ip", "size"),
                      unique_sources=("source_ip", "nunique"))
                 .reset_index())

    hits = per_sec[(per_sec["packets"] > pps_threshold)
                   & (per_sec["unique_sources"] >= min_unique_sources)]

    incidents = []
    for ip, grp in hits.groupby("destination_ip"):
        incidents.append({
            "type": "DDOS_ATTACK",
            "target": ip,
            "start": grp["second"].min(),
            "end": grp["second"].max(),
            "peak_pps": int(grp["packets"].max()),
            "unique_sources": int(grp["unique_sources"].max()),
            "severity": "HIGH",
        })
    return incidents