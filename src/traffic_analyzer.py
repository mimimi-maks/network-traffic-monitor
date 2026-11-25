"""Система мониторинга сетевого трафика предприятия."""
import warnings
from collections import defaultdict
from datetime import datetime, timedelta
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

DEPARTMENTS_LIST = ["IT", "Финансы", "Маркетинг", "HR", "Продажи", "Руководство"]
PROTOCOLS_LIST = ["HTTP", "HTTPS", "SSH", "SMTP", "FTP", "DNS", "RDP"]


class NetworkTrafficAnalyzer:
    """Класс для анализа сетевого трафика предприятия."""

    def __init__(self, company_name="ТехноПрофи"):
        self.company_name = company_name
        self.traffic_log = []
        self.alerts = []
        self.policy_violations = []

        self.security_policies = {
            "max_daily_external_traffic": 10737418240,  # 10 ГБ
            "blocked_ports": [21, 23, 135, 139, 445],
            "suspicious_ips": ["192.168.1.100", "10.0.0.15"],
            "work_hours": {"start": 9, "end": 18},
            "allowed_protocols": ["HTTP", "HTTPS", "SSH", "SMTP", "DNS"],
        }

        self.anomaly_patterns = {
            "port_scan": {"threshold": 100, "window_minutes": 5},
            "ddos_attack": {"threshold": 1000, "window_minutes": 1},
            "data_exfiltration": {"threshold": 524288000, "window_minutes": 60},
        }

        print(f"Инициализирован анализатор трафика для: {company_name}")
        print(f"Время запуска: {datetime.now()}")

    def simulate_traffic_data(self, hours=24, users=50):
        """Генерация имитационных данных трафика за `hours` часов."""
        print(f"\nГенерация имитационных данных за {hours} часов...")
        np.random.seed(42)  # воспроизводимость

        timestamps, sources, destinations = [], [], []
        protocols, ports, sizes, departments = [], [], [], []

        start_time = datetime.now() - timedelta(hours=hours)

        for _ in range(10000):
            time_offset = timedelta(seconds=int(np.random.randint(0, hours * 3600)))
            timestamps.append(start_time + time_offset)

            user_id = np.random.randint(1, users + 1)
            dept = np.random.choice(DEPARTMENTS_LIST, p=[0.1, 0.2, 0.15, 0.1, 0.3, 0.15])
            sources.append(f"192.168.1.{user_id}")
            departments.append(dept)

            if np.random.random() > 0.7:  # 30% внешний трафик
                destinations.append(
                    f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}."
                    f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
                )
            else:  # 70% внутренний
                destinations.append(f"192.168.1.{np.random.randint(1, users + 1)}")

            protocol = np.random.choice(PROTOCOLS_LIST, p=[0.3, 0.4, 0.05, 0.05, 0.05, 0.1, 0.05])
            protocols.append(protocol)

            port_map = {"HTTP": 80, "HTTPS": 443, "SSH": 22,
                        "SMTP": 25, "FTP": 21, "DNS": 53, "RDP": 3389}
            ports.append(port_map.get(protocol, int(np.random.randint(1024, 65535))))

            size = np.random.lognormal(mean=10, sigma=2)
            sizes.append(min(int(size), 65535))

        self.traffic_df = pd.DataFrame({
            "timestamp": timestamps,
            "source_ip": sources,
            "destination_ip": destinations,
            "protocol": protocols,
            "port": ports,
            "size_bytes": sizes,
            "department": departments,
        }).sort_values("timestamp").reset_index(drop=True)

        print(f"Сгенерировано {len(self.traffic_df)} записей трафика")
        return self.traffic_df

    def detect_policy_violations(self):
        """Обнаружение нарушений политик безопасности."""
        print("\n" + "=" * 60)
        print("АНАЛИЗ НАРУШЕНИЙ ПОЛИТИК БЕЗОПАСНОСТИ")
        print("=" * 60)
        violations = []

        # 1. Использование заблокированных портов
        blocked_port_violations = self.traffic_df[
            self.traffic_df["port"].isin(self.security_policies["blocked_ports"])
        ]
        if not blocked_port_violations.empty:
            print(f"  Обнаружено использование заблокированных портов: "
                  f"{len(blocked_port_violations)} случаев")
            for _, row in blocked_port_violations.head().iterrows():
                violations.append({
                    "type": "BLOCKED_PORT",
                    "timestamp": row["timestamp"],
                    "source": row["source_ip"],
                    "details": f"Использование порта {row['port']}",
                    "severity": "HIGH",
                })

        # 2. Активность в нерабочее время
        self.traffic_df["hour"] = self.traffic_df["timestamp"].dt.hour
        after_hours = self.traffic_df[
            (self.traffic_df["hour"] < self.security_policies["work_hours"]["start"]) |
            (self.traffic_df["hour"] > self.security_policies["work_hours"]["end"])
        ]
        if len(after_hours) > 100:
            print(f"  Подозрительная активность в нерабочее время: {len(after_hours)} событий")
            for dept, count in after_hours.groupby("department").size().items():
                if count > 50:
                    violations.append({
                        "type": "AFTER_HOURS_ACTIVITY",
                        "timestamp": datetime.now(),
                        "source": f"Отдел {dept}",
                        "details": f"{count} сетевых событий в нерабочее время",
                        "severity": "MEDIUM",
                    })

        # 3. Сканирование портов (правка 2: '5T' → '5min')
        self.traffic_df["time_window"] = self.traffic_df["timestamp"].dt.floor("5min")
        port_scan_candidates = self.traffic_df.groupby(
            ["source_ip", "time_window"]
        ).agg({
            "port": "nunique",
            "destination_ip": "nunique",
        }).reset_index()

        potential_scans = port_scan_candidates[
            (port_scan_candidates["port"] > 50) &
            (port_scan_candidates["destination_ip"] > 10)
        ]
        if not potential_scans.empty:
            print(f"  Обнаружено потенциальное сканирование портов: "
                  f"{len(potential_scans)} случаев")
            for _, row in potential_scans.iterrows():
                violations.append({
                    "type": "PORT_SCAN",
                    "timestamp": row["time_window"],
                    "source": row["source_ip"],
                    "details": f"Обращение к {row['port']} портам за 5 минут",
                    "severity": "HIGH",
                })

        self.policy_violations = violations
        return violations

    def analyze_traffic_patterns(self):
        """Анализ паттернов трафика."""
        print("\n" + "=" * 60)
        print("АНАЛИЗ ПАТТЕРНОВ ТРАФИКА")
        print("=" * 60)
        analysis_results = {}

        # 1. По протоколам
        protocol_distribution = self.traffic_df["protocol"].value_counts()
        print("\n  Распределение по протоколам:")
        for protocol, count in protocol_distribution.items():
            percentage = (count / len(self.traffic_df)) * 100
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        analysis_results["protocol_distribution"] = protocol_distribution

        # 2. По отделам
        print("\n  Сетевой трафик по отделам:")
        dept_traffic = self.traffic_df.groupby("department").agg({
            "size_bytes": "sum",
            "source_ip": "nunique",
        }).sort_values("size_bytes", ascending=False)
        dept_traffic["size_mb"] = dept_traffic["size_bytes"] / (1024 * 1024)
        for dept, row in dept_traffic.iterrows():
            print(f"  {dept}: {row['size_mb']:.1f} МБ от {int(row['source_ip'])} пользователей")
        analysis_results["department_traffic"] = dept_traffic

        # 3. Внешний vs внутренний
        self.traffic_df["is_external"] = ~self.traffic_df["destination_ip"].str.startswith("192.168.1.")
        external_traffic = int(self.traffic_df["is_external"].sum())
        internal_traffic = len(self.traffic_df) - external_traffic
        print(f"\n  Внешний трафик: {external_traffic} событий "
              f"({external_traffic / len(self.traffic_df) * 100:.1f}%)")
        print(f"  Внутренний трафик: {internal_traffic} событий "
              f"({internal_traffic / len(self.traffic_df) * 100:.1f}%)")

        # 4. Объём и лимит
        total_traffic_mb = self.traffic_df["size_bytes"].sum() / (1024 * 1024)
        print(f"\n  Общий объём трафика: {total_traffic_mb:.1f} МБ")
        if total_traffic_mb > (self.security_policies["max_daily_external_traffic"] / (1024 * 1024)):
            print("  ПРЕВЫШЕН ЛИМИТ ВНЕШНЕГО ТРАФИКА!")

        return analysis_results

    def generate_security_report(self):
        """Генерация отчёта по безопасности."""
        print("\n" + "=" * 60)
        print("ОТЧЕТ ПО БЕЗОПАСНОСТИ СЕТЕВОГО ТРАФИКА")
        print("=" * 60)
        print(f"Предприятие: {self.company_name}")
        print(f"Период анализа: {self.traffic_df['timestamp'].min()} - "
              f"{self.traffic_df['timestamp'].max()}")
        print(f"Всего событий: {len(self.traffic_df)}")

        if self.policy_violations:
            print(f"\n  ОБНАРУЖЕННЫЕ НАРУШЕНИЯ: {len(self.policy_violations)}")
            violation_types = defaultdict(int)
            for violation in self.policy_violations:
                violation_types[violation["type"]] += 1
            for v_type, count in violation_types.items():
                print(f"  - {v_type}: {count} случаев")
        else:
            print("\n  Критических нарушений не обнаружено")

        print("\n" + "-" * 60)
        print("РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ БЕЗОПАСНОСТИ:")
        recommendations = []

        http_count = len(self.traffic_df[self.traffic_df["protocol"] == "HTTP"])
        https_count = len(self.traffic_df[self.traffic_df["protocol"] == "HTTPS"])
        if http_count > https_count * 0.5:
            recommendations.append("Увеличить использование HTTPS вместо HTTP для шифрования трафика")

        if self.traffic_df["port"].nunique() > 100:
            recommendations.append("Рассмотреть возможность ограничения используемых портов")

        if any(v["type"] == "AFTER_HOURS_ACTIVITY" for v in self.policy_violations):
            recommendations.append("Внедрить строгий контроль доступа в нерабочее время")
        if any(v["type"] == "PORT_SCAN" for v in self.policy_violations):
            recommendations.append("Настроить IDS/IPS для автоматического блокирования сканирования портов")

        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        return recommendations

    def visualize_traffic(self):
        """Визуализация данных трафика (сохранение в docs/, правка 3)."""
        print("\n" + "=" * 60)
        print("ВИЗУАЛИЗАЦИЯ СЕТЕВОГО ТРАФИКА")
        print("=" * 60)

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle(f"Анализ сетевого трафика предприятия {self.company_name}", fontsize=16)

        self.traffic_df["hour"] = self.traffic_df["timestamp"].dt.hour
        hourly_traffic = self.traffic_df.groupby("hour").size()
        axes[0, 0].bar(hourly_traffic.index, hourly_traffic.values)
        axes[0, 0].set_title("Трафик по часам суток")
        axes[0, 0].set_xlabel("Час")
        axes[0, 0].set_ylabel("Количество событий")
        axes[0, 0].axvspan(0, 9, alpha=0.2, color="red", label="Нерабочее время")
        axes[0, 0].axvspan(18, 24, alpha=0.2, color="red")
        axes[0, 0].legend()

        protocol_dist = self.traffic_df["protocol"].value_counts()
        axes[0, 1].pie(protocol_dist.values, labels=protocol_dist.index, autopct="%1.1f%%")
        axes[0, 1].set_title("Распределение по протоколам")

        dept_traffic = self.traffic_df.groupby("department")["size_bytes"].sum() / (1024 * 1024)
        axes[1, 0].bar(dept_traffic.index, dept_traffic.values)
        axes[1, 0].set_title("Объём трафика по отделам (МБ)")
        axes[1, 0].set_xlabel("Отдел")
        axes[1, 0].set_ylabel("МБ")
        axes[1, 0].tick_params(axis="x", rotation=45)

        external_count = int(self.traffic_df["is_external"].sum())
        internal_count = len(self.traffic_df) - external_count
        axes[1, 1].bar(["Внутренний", "Внешний"], [internal_count, external_count],
                       color=["lightblue", "lightcoral"])
        axes[1, 1].set_title("Внутренний vs внешний трафик")
        axes[1, 1].set_ylabel("Количество событий")

        plt.tight_layout()
        plt.savefig("docs/network_traffic_analysis.png", dpi=150, bbox_inches="tight")
        print("📊 Графики сохранены в файл 'docs/network_traffic_analysis.png'")
        plt.close(fig)  # при Agg plt.show() не нужен