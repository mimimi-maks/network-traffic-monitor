"""Точка входа: мониторинг трафика + DDoS + аудит + оповещения + ROI."""
from src.audit_log import AuditLogger
from src.ddos_detector import detect_ddos, inject_ddos_attack
from src.notifier import Notifier
from src.roi_calculator import ROIInputs, calculate_roi, save_report
from src.traffic_analyzer import NetworkTrafficAnalyzer


def main():
    audit = AuditLogger()
    notifier = Notifier()
    analyzer = NetworkTrafficAnalyzer(company_name="ТехноПрофи")
    audit.log("SYSTEM_START", "system", {"company": analyzer.company_name})

    # Данные и DDoS-атака
    df = analyzer.simulate_traffic_data(hours=24, users=50)
    analyzer.traffic_df = inject_ddos_attack(df, target_ip="192.168.1.10")
    audit.log("DDOS_SIMULATION_INJECTED", "system", {"target": "192.168.1.10"}, "INFO")

    # Анализ
    analyzer.analyze_traffic_patterns()
    violations = analyzer.detect_policy_violations()
    for v in violations:
        audit.log("POLICY_VIOLATION", "analyzer", v, v["severity"])

    # Обнаружение DDoS
    incidents = detect_ddos(analyzer.traffic_df)
    for inc in incidents:
        audit.log("DDOS_DETECTED", "ddos_detector", inc, inc["severity"])
        notifier.alert(
            inc["severity"], "Обнаружена DDoS-атака",
            f"Цель: {inc['target']}\nПик: {inc['peak_pps']} пакетов/сек\n"
            f"Уникальных источников: {inc['unique_sources']}\n"
            f"Период: {inc['start']} — {inc['end']}",
        )
        print(f"DDoS: цель {inc['target']}, пик {inc['peak_pps']} pps")
    if not incidents:
        print("DDoS-атак не обнаружено")

    # 4. Отчёт и графики
    analyzer.generate_security_report()
    analyzer.visualize_traffic()

    # 5. Проверка целостности журнала аудита
    ok, bad_line = audit.verify()
    audit.log("AUDIT_VERIFIED", "system", {"integrity_ok": ok})
    print("Целостность журнала аудита:",
          "OK" if ok else f"НАРУШЕНА (строка {bad_line})")

    # 6. ROI (задание 2)
    params = ROIInputs()
    result = calculate_roi(params)
    save_report(params, result)
    print(f"ROI за {params.years} г.: {result['roi_percent']:.0f}%, "
          f"окупаемость: {result['payback_months']:.1f} мес. "
          f"(подробно: docs/roi_report.md)")


if __name__ == "__main__":
    main()
