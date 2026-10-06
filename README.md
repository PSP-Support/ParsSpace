# Pars Space

پنل اختصاصی **Pars Space** برای مدیریت کاربران، کانفیگ‌های VLESS، اینباندها، اشتراک‌ها و Multi Config.

این نسخه هویت مستقل Pars Space دارد و عناصر نمایشی و نام‌گذاری Spider از رابط و Preview حذف شده‌اند.

## پیش‌نمایش اختصاصی

### داشبورد
![Pars Space Dashboard](preview/assets/pars-dashboard.svg)

### ورود
![Pars Space Login](preview/assets/pars-login.svg)

### کاربران و کانفیگ
![Pars Space Users](preview/assets/pars-users.svg)

### اشتراک
![Pars Space Subscription](preview/assets/pars-subscription.svg)

### Multi Config
![Pars Space Multi Config](preview/assets/pars-multi.svg)

### نسخه موبایل
![Pars Space Mobile](preview/assets/pars-mobile.svg)

> تصاویر بالا دمو هستند و به API واقعی وصل نیستند. Preview تعاملی نیز در `preview/dashboard-review.html` قرار دارد.

## رابط موبایل و دسکتاپ

- منوی موبایل به صورت کشویی از **بالای پنل** باز می‌شود و با انیمیشن کوتاه و سبک بسته می‌شود.
- پنجره‌های ساخت، ویرایش و مشاهده روی موبایل به Bottom Sheet تمام‌عرض تبدیل می‌شوند، نه پنل باریک کناری.
- افکت‌های سنگین Blur، Mesh، Sheen و Tilt روی موبایل غیرفعال شده‌اند.
- لیست کاربران روی موبایل به کارت‌های لمسی تبدیل می‌شود.
- حرکت بین بخش‌ها و باز و بسته شدن منوها عمداً کوتاه نگه داشته شده تا روی گوشی‌های ضعیف هم سبک بماند.
- سوییچ‌های iPhone-style در RTL/LTR با موقعیت صحیح نمایش داده می‌شوند.

## کاربران و کانفیگ

- پروتکل کاربر در رابط کاربری فقط **VLESS** است و گزینه اضافی Protocol نمایش داده نمی‌شود.
- Dark Tunnel و SSH در جریان فعلی UI فعال نیستند.
- دکمه **کانفیگ** در لیست کاربران فقط پنجره مشاهده کانفیگ را باز می‌کند و فرم ساخت/ویرایش را باز نمی‌کند.
- کپی کانفیگ و لینک اشتراک با Clipboard API و fallback مرورگر انجام می‌شود.
- حجم مصرفی و حجم کل با نوار خطی نمایش داده می‌شوند.
- مصرف **۳۱ روز اخیر** برای هر کاربر قابل مشاهده است.
- Reset حجم و زمان، همان UUID و همان کانفیگ را نگه می‌دارد و دوره اعتبار ذخیره‌شده را از نو شروع می‌کند.
- Support Channel ID در ساخت کاربر و Multi Config پشتیبانی می‌شود؛ در صورت وجود، Remark با شناسه پشتیبانی ساخته شده و پسوند `PSP` به انتهای آن اضافه می‌شود.
- Alias پنل در تنظیمات سمت سرور ذخیره می‌شود و بعد از Refresh باقی می‌ماند.

## اشتراک و Multi Config

- بخش اشتراک‌ها لینک‌های per-user و Multi Config را یکجا نشان می‌دهد.
- لینک اشتراک، مصرف و حجم کل را به شکل ساده و خطی نمایش می‌دهد.
- تست Sub Link همه کانفیگ‌های VLESS استخراج‌شده از لینک را بررسی می‌کند و موارد قابل دسترس را از کمترین latency به بیشترین مرتب می‌کند.
- تست شبکه‌ای Sub Link، تست TCP reachability است و جای handshake کامل Xray را نمی‌گیرد.
- Multi Config شامل نام کلی، تعداد کانفیگ، اینباند، حجم، اعتبار، Support ID و لینک اشتراک است.
- جزئیات Multi Config مصرف، اتصال لحظه‌ای و میانگین اتصال ثبت‌شده هر کانفیگ را نمایش می‌دهد.

## ساختار

- `main.py`، Backend و API
- `static/index.html`، داشبورد Pars Space
- `static/login.html`، صفحه ورود
- `static/sub.html`، صفحه اشتراک
- `preview/dashboard-review.html`، Preview تعاملی نمایشی
- `preview/assets/`، SVGهای اختصاصی Preview
- `worker/worker.js`، Cloudflare Worker

## اجرا

متغیرهای Railway:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `SECRET_KEY`
- `DATA_DIR=/data`

برای حفظ داده‌ها، یک Volume روی `/data` قرار دهید.

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

## نکته

Preview و SVGهای README فقط دمو هستند. عملکرد واقعی کاربران، کانفیگ، اشتراک و Multi Config از API خود پنل انجام می‌شود.
