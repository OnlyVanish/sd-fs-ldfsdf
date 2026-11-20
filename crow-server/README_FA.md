# سرور انتشار و آپدیت Crow

این سرویس با Go و کتابخانه‌های استاندارد ساخته شده است. مسئولیتش فقط انتشار نسخه‌های رسمی بازی و بسته‌های فصل است؛ خود بازی بدون سرور هم اجرا می‌شود.

## امکانات

- پنل انتشار فارسی و واکنش‌گرا برای APK و ZIP فصل‌ها
- بررسی نسخه هنگام شروع برنامه و دانلود APK جدید با ProgressBar
- بررسی SHA-256، شناسه‌ی بسته (`com.crow`)، Version Code و گواهی امضای APK پیش از باز کردن نصب‌کننده
- نصب از طریق نصب‌کننده‌ی رسمی اندروید با تأیید کاربر؛ نصب مخفیانه/بی‌اجازه انجام نمی‌شود
- دانلود و نصب خودکار بسته‌های فصل در شروع بازی؛ پیشرفت بازی و localStorage پاک نمی‌شود
- ذخیره‌ی فایل‌ها در `/opt/crow-server/data` و حفظ آن‌ها بعد از Restart سرویس
- هش رمز با PBKDF2-HMAC-SHA256، نشست تصادفی، Cookieهای Secure/HttpOnly/SameSite=Strict، CSRF و محدودیت تلاش ورود
- اعتبارسنجی ZIP فصل، مقابله با Zip Slip و محدودیت تعداد/اندازه‌ی فایل‌ها

## مسیرها

- `GET /healthz`
- `GET /api/v1/app`
- `GET /api/v1/app/download`
- `GET /api/v1/seasons`
- `GET /api/v1/seasons/{id}/download`
- پنل مدیریت: مقدار `ADMIN_PATH` به‌علاوه‌ی `/`

## نصب روی Ubuntu

نیازمندی‌ها: Go نسخه‌ی 1.22 یا بالاتر، Caddy نسخه‌ی 2.11 یا بالاتر، دسترسی root، و باز بودن ورودی پورت‌های TCP 80 و 443 در فایروال سرور و پنل دیتاسنتر.

### ۱) نصب Caddy از مخزن رسمی

```bash
sudo apt update
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
sudo chmod o+r /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
caddy version
```

خروجی Caddy باید 2.11.0 یا جدیدتر باشد. این نسخه در Caddyfile از پروفایل ACME کوتاه‌عمر برای گواهی HTTPS روی IP استفاده می‌کند.

### ۲) آپلود و نصب سورس

پوشه‌ی `crow-server` را روی VPS کپی کن؛ سپس از همان پوشه اجرا کن:

```bash
sudo bash deploy/install-ubuntu.sh
```

اسکریپت کاربر محدود `crow`، دایرکتوری داده، سرویس systemd و Caddyfile را می‌سازد. سرویس Go فقط روی `127.0.0.1:8090` گوش می‌دهد و از اینترنت مستقیم در دسترس نیست.

### ۳) ساخت هش رمز و تنظیم پنل

رمزی که قبلاً در چت نوشته شده را برای پنل استفاده نکن؛ یک رمز جدید، منحصربه‌فرد و طولانی انتخاب کن. برای اینکه رمز در ترمینال نمایش داده نشود:

```bash
read -s -p 'New admin password: ' PW; echo
printf '%s\n' "$PW" | /opt/crow-server/crow-server hash-password
unset PW
```

خروجی `pbkdf2-sha256$...` را کپی کن. سپس فایل زیر را باز کن:

```bash
sudo nano /opt/crow-server/.env
```

مقادیر نمونه:

```dotenv
CROW_ADDR=127.0.0.1:8090
CROW_DATA_DIR=/opt/crow-server/data
ADMIN_USERNAME=Admin
ADMIN_PASSWORD_HASH=خروجی-هش-اینجا
ADMIN_PATH=/یک-مسیر-تصادفی-حداقل-۴۸-رقمی
```

برای ساخت مسیر تصادفی:

```bash
printf '/panel-%s\n' "$(openssl rand -hex 24)"
```

مسیر پنل و رمز را در سورس عمومی، گروه‌ها یا اسکرین‌شات‌ها منتشر نکن. مسیر طولانی فقط یک لایه‌ی کاهش سطح دیده‌شدن است و جای رمز/HTTPS را نمی‌گیرد.

سپس:

```bash
sudo chown root:crow /opt/crow-server/.env
sudo chmod 0640 /opt/crow-server/.env
sudo systemctl restart crow
sudo systemctl restart caddy
sudo systemctl status crow --no-pager
sudo journalctl -u caddy -n 80 --no-pager
```

اگر Caddy نتواند گواهی بگیرد، معمولاً پورت 80/443 بسته است یا IP عمومی این سرور به همین دستگاه/ماشین مجازی route نشده است. HTTPS را غیرفعال نکن و اپ را به HTTP تغییر نده.

### ۴) تست

```bash
curl -fsS https://185.26.33.188/healthz
```

نشانی پنل:

`https://185.26.33.188/<ADMIN_PATH>/`

## انتشار APK

1. APK نسخه‌ی اولی که updater دارد باید با `applicationId=com.crow`، `versionCode=4` و `versionName=1.4` ساخته شود.
2. این نسخه‌ی اول را یک‌بار به‌صورت دستی به کاربران فعلی برسان و نصب کن. نسخه‌های قدیمی updater ندارند و نمی‌توانند از سرور خودشان را به نسخه‌ی اول ارتقا دهند.
3. بعد از آن، برای هر انتشار `versionCode` را افزایش بده؛ مثلاً 5، 6، 7. هرگز آن را کم یا مساوی نسخه‌ی منتشرشده انتخاب نکن.
4. از پنل، Version Code، Version Name، توضیحات و APK را ثبت کن. فایل فقط پس از اعتبارسنجی اولیه و ثبت SHA-256 منتشر می‌شود.
5. در شروع اجرای بعدی، نسخه با سرور مقایسه، فایل دانلود، هش/Package/Version/امضا بررسی و پنجره‌ی نصب‌کننده‌ی سیستم باز می‌شود.

**کلید امضای قبلی حیاتی است:** برای نصب روی نسخه‌ی فعلی بدون حذف برنامه، APK جدید باید با همان کلید خصوصی‌ای امضا شود که نسخه‌ی فعلی Crow با آن امضا شده است. فایل keystore داخل ZIP ارسالی وجود نداشت. گواهی عمومی APK قبلی قابل استخراج است، ولی از روی آن نمی‌توان کلید خصوصی را بازسازی کرد. اگر keystore اصلی را نداری، این APK به‌روزرسانی مستقیم نسخه‌ی نصب‌شده نخواهد بود؛ نصب مجدد ممکن است به حذف برنامه و از دست رفتن اطلاعات محلی نیاز داشته باشد. قبل از انتشار، این موضوع را با یک دستگاه آزمایشی بررسی کن.

اندروید اجازه‌ی نصب خاموش و بدون تأیید کاربر را نمی‌دهد. کاربر باید مجوز «نصب برنامه از این منبع» را برای Crow فعال کند و سپس تأیید خود نصب‌کننده را انجام دهد. بعد از موفقیت نصب، نسخه‌ی تازه دوباره اجرا می‌شود. اگر بازی از Google Play توزیع شود، این روش خودآپدیت مناسب سیاست Play نیست؛ مسیر به‌روزرسانی Play باید جداگانه استفاده شود.

## انتشار فصل بدون APK جدید

پنل ZIP با فرمت `crow-season-pack` را می‌پذیرد. در ZIP باید `pack.json` و فایل JavaScript با مسیر `entry` باشد. نمونه و مستند API در `CROW_SEASON_PACKS_FA.md` ریشه‌ی پروژه است. شناسه‌ی فصل را ثابت نگه دار، نسخه‌ی همان فصل را افزایش بده و `order` را بالاتر از فصل‌های قبلی قرار بده.

فصل‌های ۹ تا ۱۶ فعلاً داخل APK نسخه‌ی 1.4 قرار داده شده‌اند؛ فصل‌های جدید بعدی می‌توانند از بخش انتشار فصل پنل دریافت شوند. بسته‌های فصل اسکریپت JavaScript اجرایی هستند؛ فقط محتوایی را منتشر کن که خودت ساخته و به آن اعتماد داری.

## نگهداری و بازیابی

- از کل مسیر `/opt/crow-server/data` نسخه‌ی پشتیبان منظم بگیر.
- رمز و مقدار `ADMIN_PATH` را داخل Git/ZIP نگذار.
- در صورت شک به افشای رمز، رمز جدید بساز و `ADMIN_PASSWORD_HASH` را جایگزین کن.
- اگر APK/فصل اشتباهی منتشر شد، فایل‌ها و JSONهای حالت در `/opt/crow-server/data` را از نسخه‌ی پشتیبان معتبر بازیابی کن؛ در نسخه‌ی فعلی پنل دکمه‌ی Rollback/Delete وجود ندارد.
