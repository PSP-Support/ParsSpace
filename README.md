# 🏛️ Pars Space

Pars Space یک پنل مدیریتی مدرن برای مدیریت User، Config، Subscription، Inbound و Node است.

## ✨ امکانات

- مدیریت کاربران، حجم و تاریخ انقضا
- محدودیت دستگاه همزمان برای هر کاربر
- Subscription اختصاصی + QR
- VLESS / VMess / Trojan / Reality
- SNI و Fingerprint برای کانفیگ‌ها
- مدیریت Inbound و حذف Inbound
- Node با Health Check، Sync و نمایش کانفیگ‌های سینک‌شده
- SNI Scanner
- Config Test
- API اختصاصی Pars Space
- فارسی / انگلیسی
- Dark / Light
- رابط Responsive و بهینه‌تر برای موبایل

## 🚀 نصب سریع

### Linux / VPS

```bash
sudo apt update
sudo apt install -y git python3 python3-venv

git clone YOUR_GITHUB_REPOSITORY ParsSpace
cd ParsSpace
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8080
```

پنل:

```text
http://SERVER-IP:8080/spider
```

### Windows

CMD:

```cmd
git clone YOUR_GITHUB_REPOSITORY ParsSpace
cd ParsSpace
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8080
```

### Android / Termux

```bash
pkg update -y
pkg install python git -y
git clone YOUR_GITHUB_REPOSITORY ParsSpace
cd ParsSpace
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8080
```

سپس `http://127.0.0.1:8080/spider` را باز کنید.

## 🔑 Secret Key

CMD یا Terminal:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

بعد مقدار خروجی را به عنوان `SECRET_KEY` در Environment قرار دهید.

## ☁️ Railway

Repository را به Railway وصل کنید، Deploy را انجام دهید و Domain عمومی بسازید. برنامه روی پورت 8080 اجرا می‌شود.

## 🛰️ Node

Node باید قبل از ساخت کاربر، یک Inbound موجود و سالم داشته باشد. Pars Space هنگام ساخت کاربر برای Node جدید Inbound اضافی نمی‌سازد. برای VMess/Trojan نیز باید Inbound همان پروتکل روی Node مقصد از قبل ساخته شده باشد تا همان Config روی Node ساخته و در پنل اصلی نمایش داده شود.

## 🔐 نکات امنیتی

- Secret Key، API Key و رمزها را داخل GitHub نگذارید.
- پنل عمومی را با HTTPS اجرا کنید.
- Scanner را فقط روی مقصدهایی که اجازه بررسی آن‌ها را دارید اجرا کنید.
- VMess به زمان دقیق سیستم حساس است.

## 📌 ساختار

```text
ParsSpace/
├── main.py
├── public_page.py
├── requirements.txt
├── Dockerfile
├── Procfile
├── railway.toml
└── static/
    ├── index.html
    ├── login.html
    └── sub.html
```
