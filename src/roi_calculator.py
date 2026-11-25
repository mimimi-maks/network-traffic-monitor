"""Расчёт ROI от внедрения системы мониторинга сетевого трафика."""
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ROIInputs:
    years: int = 3
    # --- Затраты ---
    implementation_cost: float = 1_500_000        # разработка/внедрение, единоразово
    annual_license_and_support: float = 600_000   # лицензии, сервер, поддержка в год
    annual_staff_cost: float = 900_000            # доля ставки специалиста ИБ в год
    # --- Инциденты безопасности (данные Ponemon/IBM, масштабированные под компанию) ---
    incident_cost: float = 15_000_000             # стоимость одного серьёзного инцидента
    incidents_per_year_before: float = 0.3        # ожидаемое число инцидентов в год
    incident_reduction: float = 0.6               # доля снижения ущерба
    # --- Доступность (снижение простоя) ---
    downtime_hours_per_year_before: float = 40
    downtime_reduction: float = 0.5
    cost_per_downtime_hour: float = 120_000
    # --- Утечки данных ---
    leak_loss_per_year_before: float = 3_000_000
    leak_reduction: float = 0.5


def calculate_roi(p: ROIInputs):
    benefit_incidents = p.incident_cost * p.incidents_per_year_before * p.incident_reduction
    benefit_downtime = (p.downtime_hours_per_year_before * p.downtime_reduction
                        * p.cost_per_downtime_hour)
    benefit_leaks = p.leak_loss_per_year_before * p.leak_reduction
    annual_benefit = benefit_incidents + benefit_downtime + benefit_leaks

    annual_running = p.annual_license_and_support + p.annual_staff_cost
    total_cost = p.implementation_cost + annual_running * p.years
    total_benefit = annual_benefit * p.years
    net = total_benefit - total_cost
    roi_percent = net / total_cost * 100

    net_annual = annual_benefit - annual_running
    payback_months = (p.implementation_cost / net_annual * 12) if net_annual > 0 else None

    return {
        "benefit_incidents": benefit_incidents,
        "benefit_downtime": benefit_downtime,
        "benefit_leaks": benefit_leaks,
        "annual_benefit": annual_benefit,
        "total_benefit": total_benefit,
        "total_cost": total_cost,
        "net_effect": net,
        "roi_percent": roi_percent,
        "payback_months": payback_months,
    }


def save_report(p: ROIInputs, r: dict, path="docs/roi_report.md"):
    rub = lambda x: f"{x:,.0f} ₽".replace(",", " ")
    payback = f"{r['payback_months']:.1f} мес." if r["payback_months"] else "не окупается"
    text = f"""# Бизнес-кейс: ROI системы мониторинга сетевого трафика («ТехноПрофи»)

Горизонт расчёта: {p.years} года.

## Затраты
| Статья | Сумма |
|---|---|
| Внедрение (единоразово) | {rub(p.implementation_cost)} |
| Лицензии и поддержка (в год) | {rub(p.annual_license_and_support)} |
| Персонал ИБ (в год) | {rub(p.annual_staff_cost)} |
| **Итого за {p.years} г.** | **{rub(r['total_cost'])}** |

## Выгоды (в год)
| Источник эффекта | Сумма |
|---|---|
| Снижение ущерба от инцидентов ИБ | {rub(r['benefit_incidents'])} |
| Снижение потерь от простоя (availability) | {rub(r['benefit_downtime'])} |
| Сокращение потерь от утечек данных | {rub(r['benefit_leaks'])} |
| **Итого за год** | **{rub(r['annual_benefit'])}** |

## Результат
- Совокупная выгода за {p.years} г.: {rub(r['total_benefit'])}
- Чистый эффект: {rub(r['net_effect'])}
- **ROI = (Выгода − Затраты) / Затраты × 100% = {r['roi_percent']:.0f}%**
- Срок окупаемости: {payback}

> Допущение: часть эффекта от инцидентов и утечек может пересекаться; значения
> в `ROIInputs` — учебные и подлежат замене на данные организации.
"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
    return text