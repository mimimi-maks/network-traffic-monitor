"""Оповещения в Telegram и Slack."""
import os

import requests
from dotenv import load_dotenv

load_dotenv()


class Notifier:
    def __init__(self):
        self.tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.tg_chat = os.getenv("TELEGRAM_CHAT_ID")
        self.slack_url = os.getenv("SLACK_WEBHOOK_URL")

    def send_telegram(self, text):
        if not (self.tg_token and self.tg_chat):
            print(f"[Telegram dry-run] {text}")
            return False
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{self.tg_token}/sendMessage",
                json={"chat_id": self.tg_chat, "text": text},
                timeout=10,
            )
            return r.ok
        except requests.RequestException as e:
            print(f"[Telegram] ошибка отправки: {e}")
            return False

    def send_slack(self, text):
        if not self.slack_url:
            print(f"[Slack dry-run] {text}")
            return False
        try:
            r = requests.post(self.slack_url, json={"text": text}, timeout=10)
            return r.ok
        except requests.RequestException as e:
            print(f"[Slack] ошибка отправки: {e}")
            return False

    def alert(self, severity, title, details):
        text = f"🚨 [{severity}] {title}\n{details}"
        return {"telegram": self.send_telegram(text),
                "slack": self.send_slack(text)}
