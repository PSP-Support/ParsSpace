# Pars Space 🚀

پنل مدیریتی **Pars Space** برای مدیریت کاربران، کانفیگ‌ها، Subscription، Inbound و Nodeها.

## ✨ امکانات

- 👤 مدیریت کاربران
- 📊 حجم، انقضا و محدودیت دستگاه همزمان
- 🔗 Subscription اختصاصی + QR
- ⚡ VLESS / VMess / Trojan / Reality
- 🌐 مدیریت Inbound
- 🖥️ اتصال چند پنل به عنوان Node
- 🔄 Sync کاربر و کانفیگ بین Nodeها
- 🔎 SNI Scanner
- 🧪 Config Test
- 🔐 Pars Space API با کلید `psp_`
- 🌙 Dark / Light / System
- 🇮🇷 فارسی / 🇬🇧 انگلیسی
- 📱 مناسب موبایل و کامپیوتر
- ✨ رابط Liquid Glass

## 🎯 هدف پروژه

هدف Pars Space اینه که مدیریت سرویس و کاربران ساده‌تر بشه.  
ساخت کاربر، انتخاب Inbound، ساخت Subscription و اتصال به Nodeها از یک محیط انجام میشه.

مخصوصاً در بخش Node، کاربر می‌تونه یک Inbound از نوع **Node** داشته باشه، چند Node رو انتخاب کنه و کانفیگ واقعی ساخته‌شده روی Node رو مستقیماً از پنل دریافت کنه.

---

# 📦 نصب روی کامپیوتر

## Windows

Python و Git رو نصب کنید، بعد CMD:

```cmd
git clone YOUR_GITHUB_REPOSITORY
cd ParsSpace
pip install -r requirements.txt
python main.py
```

بعد:

```text
http://127.0.0.1:8080
```

اگر پورت دیگری در Terminal نمایش داده شد، همان پورت را استفاده کنید.

## Linux

```bash
git clone YOUR_GITHUB_REPOSITORY
cd ParsSpace
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

یا:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8080
```

---

# 📱 نصب روی Android

با **Termux**:

```bash
pkg update -y
pkg install python git -y

git clone YOUR_GITHUB_REPOSITORY
cd ParsSpace

pip install -r requirements.txt
python main.py
```

بعد مرورگر گوشی:

```text
http://127.0.0.1:8080
```

---

# 🔑 ساخت Secret Key

داخل CMD یا Terminal:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

یا داخل Python:

```python
import secrets
print(secrets.token_urlsafe(32))
```

کلید را داخل Environment پروژه قرار بدهید و داخل GitHub منتشر نکنید.

---

# 🌐 راه‌اندازی Node

در پنل مقصد از بخش Settings، **Pars Space API Key** را بگیرید.

کلید باید با این شکل باشد:

```text
psp_xxxxxxxxxxxxxxxxx
```

در پنل اصلی:

```text
Nodes
→ Add Node
→ Node name
→ Panel URL
→ Panel API Key
→ Connect
```

بعد از اتصال، Node باید وضعیت آنلاین و اطلاعات Inboundهای قابل استفاده را نشان بدهد.

برای استفاده:

```text
Inbounds
→ Node
→ انتخاب Node
→ Save
```

حالا هنگام ساخت کاربر، Inbound نوع Node را انتخاب کنید.

Pars Space بر اساس پروتکل کاربر، Inbound سازگار روی Node را انتخاب می‌کند و کانفیگ واقعی همان Node را برمی‌گرداند.

---

# 👤 ساخت کاربر

از:

```text
Users & Config
→ ایجاد کاربر + کانفیگ
```

موارد اصلی:

- Username
- Protocol
- Inbound
- Traffic
- Expire days
- SNI
- Device limit

محدودیت دستگاه:

```text
نامحدود
1
2
3
4
5
10
سفارشی
```

برای VMess و Trojan لازم نیست Password کانفیگ را دستی وارد کنید. اطلاعات لازم به‌صورت خودکار ساخته می‌شود.

---

# 🌐 Inbound

Inbound پیش‌فرض همیشه:

```text
VLESS + WebSocket + TLS
```

است.

برای ساخت Inbound جدید می‌توانید از:

```text
VLESS
VMess
Trojan
Reality
```

استفاده کنید.

SNI و Fingerprint در تنظیمات Inbound قابل انتخاب هستند.

Fingerprintهای موجود:

```text
chrome
firefox
safari
ios
android
edge
360
qq
random
randomized
```

---

# 🛰️ VMess و Trojan

VMess و Trojan به‌صورت پروتکل واقعی خودشان ساخته می‌شوند و به VLESS تبدیل نمی‌شوند.

برای Trojan، Password اختصاصی کاربر در Backend نگهداری می‌شود و در UI لازم نیست دستی وارد شود.

برای VMess، UUID کاربر به‌عنوان شناسه کلاینت استفاده می‌شود.

---

# 🧹 حذف Inbound

از بخش:

```text
Inbounds
→ Delete
```

می‌توانید Inboundهای معمولی را حذف کنید.

Inbound سیستمی `Node` قابل حذف نیست، چون وظیفه‌اش نگهداری انتخاب Nodeهاست.

---

# 📱 بهینه‌سازی موبایل

Pars Space در نسخه فعلی:

- Loader اولیه دارد
- داده‌های اصلی را قبل از نمایش کامل صفحه دریافت می‌کند
- افکت‌های سنگین موبایل کاهش داده شده‌اند
- Blur روی موبایل سبک‌تر است
- بخش‌های سنگین به‌صورت جداگانه بارگذاری می‌شوند
- جدول‌ها و لیست‌ها برای موبایل بهینه شده‌اند

---

# 🛠️ نکات مهم

برای استفاده عمومی:

- HTTPS فعال باشد
- Secret Key و API Key را منتشر نکنید
- دسترسی Admin را محدود کنید
- برای Nodeها از API Key معتبر استفاده کنید
- SNI و Domain واقعی خودتان را وارد کنید
- قبل از استفاده عمومی، Config تولیدشده را با کلاینت واقعی تست کنید

## 📌 وضعیت پروژه

Pars Space یک پروژه در حال توسعه است. قبل از استفاده روی زیرساخت واقعی، تنظیمات شبکه، Xray و Certificateهای موردنیاز پروتکل‌ها را بررسی کنید.

**Pars Space · Simple management, real control.**
