# 07 — UI Tasarımı

## 1. Skill/kaynak keşfi

Oturumda mevcut skill'ler tarandı: genel amaçlı bir frontend/tasarım sistemi/erişilebilirlik skill'i yok (mevcutlar belge, sunum, veri görselleştirme ve Artifact sayfalarına özel). Harici skill kurulmadı. Tasarım, aşağıdaki ilkelerle proje içinde elle yazılan küçük bir CSS sistemidir; üçüncü parti CSS/JS/font bağımlılığı yoktur.

## 2. Kimlik

| Uygulama | Ad | Karakter | Vurgu rengi |
|---|---|---|---|
| IAM | **Halka ID** | Sakin, kurumsal, yoğun bilgi | Koyu çelik mavisi `#1f4b7a` |
| Client A | **Pano** | Ekip not panosu | Yeşil `#1d6b4f` |
| Client B | **Rapor** | Salt-okunur raporlama | Kiremit `#9a4a1f` |

Üç uygulama görsel olarak ayrışır (başlık şeridi rengi + ad + favicon harfi); böylece SSO sırasında hangi origin'de olunduğu açıktır. Loca/Kulvar veya başka üründen kopya yoktur.

Yasaklar: mor gradient, glow, 3D/marketing görselleri, anlamsız kart duvarı. Düz yüzeyler, ince çizgiler, tek vurgu rengi.

## 3. Tasarım belirteçleri

- Tipografi: sistem font yığını (`system-ui, "Segoe UI", Roboto, sans-serif`); kod için `ui-monospace`. Harici/yerel font dosyası yok → lisans yükü yok.
- Ölçek: 14/16/20/24/32 px; satır yüksekliği 1.5; boşluk 4 px ızgara.
- Renk: nötr gri zemin `#f6f7f9`, yüzey `#ffffff`, metin `#16202b`, ikincil `#51606f`, sınır `#d5dbe2`; durum renkleri: başarı `#1d6b4f`, uyarı `#8a5a00`, tehlike `#a3261f`. Tüm metin/zemin çiftleri WCAG AA (≥ 4.5:1).
- Koyu tema: `prefers-color-scheme: dark` ile aynı belirteçlerin koyu karşılıkları.
- Hareket: yalnız 120 ms renk/opaklık geçişi; `prefers-reduced-motion: reduce` altında tümü kapalı.
- Focus: 2 px belirgin halka (`:focus-visible`), hiçbir yerde `outline: none` bırakılmaz.

## 4. Yerleşim

- 360 px: tek sütun, üstte kompakt başlık, gezinme `<details>` ile açılır; tablolar etiketli satır kartlarına döner.
- 768 px: tek sütun içerik + yatay gezinme.
- 1440 px: sol sabit gezinme (admin/hesap) + en çok 1100 px içerik.

## 5. Ekranlar

### Kullanıcı
| Ekran | İçerik | Kritik durumlar |
|---|---|---|
| Sign in | E-posta, parola, hata özeti (`role="alert"`) | Generic hata, lockout aynı mesaj, 429 |
| MFA challenge | 6 haneli tek alan (`inputmode="numeric"`, `autocomplete="one-time-code"`, yapıştırma destekli), "Use a recovery code" bağlantısı | Süresi dolmuş challenge, deneme limiti |
| Recovery | Tek kod alanı | Kullanılmış/geçersiz kod |
| Sign up / confirm | Form → "check the demo mail sink" bilgisi → doğrulama sonucu | Generic yanıt |
| Forgot / reset | E-posta → generic onay; yeni parola formu | Süresi dolmuş/kullanılmış token |
| Consent | Client adı, client id, istenen scope'lar ve açıklamaları, Allow / Deny | Hangi hesapla onaylandığı görünür |
| Step-up | Neden istendiği + TOTP (yoksa parola) | Dönüş yalnız yerel yol |
| Account overview | Profil, MFA durumu, oturum sayısı, bağlı uygulamalar | |
| MFA enroll | Yerelde üretilen QR (SVG) + elle girilecek anahtar + doğrulama kodu | Secret yalnız bu ekranda, `no-store` |
| Recovery codes | Kodlar bir kez gösterilir, kopyala/yazdır | Sayfa yenilenince kodlar yok |
| Sessions | Oturum listesi (bu cihaz rozeti), tekil iptal, "Sign out everywhere" | Onay diyaloğu |
| Connected apps | Client, scope'lar, onay tarihi, "Revoke access" | |
| Activity | Kendi güvenlik olayları | |

### Admin
| Ekran | İçerik |
|---|---|
| Dashboard | Sayılar + ops özeti + step-up durumu |
| Users / User detail | Arama; durum, roller, MFA, oturumlar, grant'ler; disable/enable/unlock, rol değişikliği (PlatformAdmin), oturum/grant iptali |
| Clients / New / Detail | Tür, URI allowlist, scope'lar, consent; disable/enable; secret rotate (grace seçimi) → **tek seferlik secret ekranı** |
| Scopes | Liste + ekleme |
| Sessions / Grants | Aktif kayıtlar, filtre, iptal |
| Audit | Zaman, aktör, eylem, hedef, sonuç, correlation; filtre |
| Keys | Anahtar listesi (kid, kullanım, durum, zamanlar), rotate, retire (erken ise neden devre dışı olduğu yazılır), emergency revoke (risk metni + yazarak onay) |
| Ops | DB, anahtar halkası, outbox kuyruğu/dead sayısı, sürüm |

İlke: "istek kabul edildi" ile "uygulandı" ayrımı. İptal eylemleri senkron uygulanır ve sonuç ekranı gerçek durumu (kaç oturum/grant iptal edildi) DB'den okuyarak gösterir. Bağlanmamış buton veya sahte başarı yoktur.

### Demo istemciler (Pano / Rapor)
- Başlıkta app-local oturum rozeti (Signed in / Signed out), kullanıcı adı.
- Session sayfası: sub (kısaltılmış), scope'lar, `amr`, `auth_time`, access token bitişi — ham token/secret asla.
- Workspace sayfası: "Load notes", "Add note", "Load sensitive notes", her sonuç için durum satırı (200 / 403 insufficient scope / 403 step-up / 401 / 503).
- "Refresh tokens now", "Sign in again (fresh)", "Sign out of <app> only", "Sign out everywhere".
- Teknik panel (`<details>`) yalnız Development ortamında: son token işlemi sonucu, discovery issuer'ı.

## 6. Erişilebilirlik sözleşmesi

- Her form alanı görünür `<label>`; hata mesajları `aria-describedby` ile bağlı; hata özeti `role="alert"`.
- Tek `<h1>`; landmark'lar (`header/nav/main/footer`); "Skip to content" bağlantısı.
- Tablolar `<caption>` + `scope` taşır; dar ekranda `data-label` ile satır kartı.
- Tehlikeli eylemler: ayrı onay adımı veya yazarak onay; yalnız renkle bilgi verilmez.
- Kod girişi: tek input, yapıştırma destekli, boşluk/tire temizlenir (JS yoksa sunucu temizler).
- Otomatik kontrol: axe-core (Playwright) + klavye gezinme testi. Ekran okuyucu ile elle test bu çalışmada **yapılmamıştır** (bkz. `known-limitations.md`).

## 7. Güvenlikle ilgili UI kuralları

- Auth ekranlarında harici script/font/görsel isteği yok; CSP `default-src 'self'`.
- Hassas sayfalar `Cache-Control: no-store`; logout `Clear-Site-Data: "cache"`.
- Secret/QR/recovery code `localStorage`/`sessionStorage`'a yazılmaz; JS yalnız DOM'da kopyalama yapar.
- Authorization/logout tarayıcı navigasyonuyla (form/link) yapılır; `fetch` ile yapılmaz.

## 8. Statik önizleme

`design/preview.html`: bileşen ve ekran iskeletlerinin statik demosu (gerçek API'ye bağlı değildir; yalnız görsel sözleşme). Nihai UI gerçek sunucu verisiyle çalışır.
