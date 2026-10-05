# Pars Space v7 update

این نسخه بر پایه ParsSpace v6 ساخته شده و تغییرات اصلی زیر را دارد:

- اصلاح Xray native protocol clients برای VMess / Trojan / VLESS + Reality.
- Trojan فقط با `password` به Xray داده می‌شود و UUID به client آن اضافه نمی‌شود.
- VMess client با UUID و `alterId: 0` ساخته می‌شود.
- VLESS/Reality همچنان با `decryption: none` ساخته می‌شود.
- اعتبارسنجی Xray برای clientهای VMess/Trojan اضافه شد.
- Config Builder از لیست عادی کاربران جدا شده و فقط با دکمه «ایجاد کاربر + کانفیگ» باز می‌شود.
- کپی مستقیم کانفیگ اضافه شد.
- ویرایش کامل اطلاعات اینباند از همان modal ایجاد/ویرایش انجام می‌شود.
- Activity و Logs به Settings منتقل شدند.
- نام مستعار پنل در Settings قابل تنظیم است.
- کشور سرور در Settings با نام و پرچم نمایش داده می‌شود.
- داشبورد دارای نمودار زنده ترافیک با بازه ساعت/روز/هفته/ماه، حجم بازه، میانگین اتصال و اوج اتصال است.
- Speed Test دارای نمایش گرافیکی سرعت دانلود و meter است.
- Subscription page برای کانفیگ‌های طولانی از overflow امن و wrapping استفاده می‌کند.
- Login: تصویر سمت چپ، فرم سمت راست، hover/animation بیشتر و greeting تصادفی.
- Loading screen اولیه برای دسکتاپ و موبایل اضافه شد.
- Light/Dark خواناتر و متعادل‌تر شدند.
- SNI scanner از لیست `data/sni_reality_for_scan.txt` استفاده می‌کند و کل لیست را برای تست می‌فرستد.
- لیست SNI فعلی کاربر داخل همین فایل runtime قرار داده شده است.
- Config generator برای client address دیگر IP خام پنل را به‌عنوان hostname خروجی نمی‌دهد. اگر hostname عمومی تنظیم نشده باشد، خروجی config عمداً خالی می‌ماند تا IP پنل افشا نشود.

## Test note

در محیط ساخت فعلی Xray binary نصب نشده است، بنابراین تست واقعی اتصال شبکه Xray قابل اثبات نبود. تست ساخت config و validation سمت پنل انجام شده است. برای تست live باید binary Xray و پورت‌های واقعی محیط deploy در دسترس باشند.
