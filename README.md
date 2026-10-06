# Pars Space

پنل مدیریت و اشتراک **Pars Space** با تمرکز روی VLESS، مدیریت کاربران، لینک‌های اشتراک و Multi Config. این نسخه UI و Preview اختصاصی Pars Space دارد و ساختار نمایشی آن مستقل طراحی شده است.

## نمای سریع

### داشبورد
![Pars Space Dashboard](preview/assets/pars-dashboard.svg)

### ورود
![Pars Space Login](preview/assets/pars-login.svg)

### اشتراک
![Pars Space Subscription](preview/assets/pars-subscription.svg)

### کاربران
![Pars Space Users](preview/assets/pars-users.svg)

## امکانات این نسخه

- رابط اختصاصی Pars Space با تم مشکی و طلایی، Light / Dark / System
- منوی موبایل کشویی از بالا با انیمیشن کوتاه و سبک
- VLESS به‌عنوان پروتکل کاربر در این UI، بدون گزینه پروتکل اضافه
- حذف Dark Tunnel و SSH از جریان فعلی ساخت کاربر
- نمایش کانفیگ در پنجره مستقل، بدون باز شدن فرم ویرایش/ایجاد کاربر
- کپی مستقیم کانفیگ و لینک اشتراک با fallback برای مرورگرهای بدون Clipboard API
- نمایش حجم مصرفی و حجم کل به‌صورت خطی
- تاریخچه مصرف روزانه ۳۱ روز اخیر برای هر کاربر
- ریست هم‌زمان حجم و زمان، با استفاده مجدد از همان کانفیگ
- نام مستعار پنل با ذخیره‌سازی سمت سرور
- آیدی کانال پشتیبانی در Remark؛ به‌جای نام Pars Space و با پسوند `PSP` در انتهای Remark
- صفحه اشتراک‌ها شامل لینک‌های شخصی کاربران و اشتراک‌های گروهی / Multi Config
- Multi Config: تعداد کانفیگ، اینباند، نام مشترک، حجم، زمان، Support ID و یک لینک اشتراک واحد
- جزئیات Multi Config شامل اتصال لحظه‌ای، مصرف و میانگین ثبت‌شده اتصالات
- تست یک کانفیگ VLESS و تست کل Sub Link، با مرتب‌سازی نتیجه‌های قابل دسترس بر اساس کمترین پینگ
- Preview مستقل برای بررسی ظاهر، بدون ادعای اتصال به API واقعی

## اجرا

متغیرهای Railway قبل از استقرار:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `SECRET_KEY`
- `DATA_DIR=/data`

برای حفظ کاربران و تنظیمات، یک Volume روی `/data` قرار بده.

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

## ساختار

- `main.py`، Backend و API
- `static/index.html`، داشبورد واقعی Pars Space
- `static/login.html`، صفحه ورود
- `static/sub.html`، صفحه اشتراک
- `preview/dashboard-review.html`، Preview نمایشی مستقل
- `preview/assets/`، SVGهای اختصاصی README و Preview
- `worker/worker.js`، Cloudflare Worker جداگانه

## نکته فنی تست Sub

تست Sub Link در این نسخه **TCP reachability / latency** را بررسی می‌کند. یعنی پایین‌ترین پینگ را از نظر دسترسی شبکه مرتب می‌کند، نه اینکه اجرای کامل handshake یک کلاینت Xray را شبیه‌سازی کند. انسان‌ها ظاهراً هنوز دوست دارند یک تست TCP را اسمش را «تست کامل کانفیگ» بگذارند، پس اینجا دقیقش نوشته شده.

## وضعیت Preview

Preview فقط دمو است و داده واقعی تولید نمی‌کند. برای تست API واقعی از خود `/dashboard` استفاده کن.
