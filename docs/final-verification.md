# Son Doğrulama

**Tarih:** 2026-10-11 · **Ortam:** Windows 11, .NET SDK 10.0.401, Docker Engine 29.8.2 + Compose v5.5.1, kurulu
Chrome, PostgreSQL 17 (Testcontainers / Compose) · **Uzak CI:** koşulmadı.

**Bu belgede iki kaynak durumu vardır; sonuçlar birbirine taşınmaz.**

| Kayıt | Kaynak fingerprint'i (`./scripts/source-fingerprint.ps1`; `docs/` ve `artifacts/` kapsam dışı) | Ne koşuldu |
|---|---|---|
| A — final kapıları (bölüm 1–5) | `sha256:15015539afab3692006971ed65611ddfaefc93154ce5320822f69e1e007e12c9` (248 dosya) | Bütün yerel kapılar |
| B — iki kozmetik düzeltme (bölüm 6) | `sha256:47adc621657715d0d0a98ecad97e0a86f416a65a208a90a8f4a56e13a135573d` (248 dosya) — **güncel kaynak** | Yalnız değişiklikten etkilenen kontroller |

Güncel kaynak B'dir. Birim (62), tam entegrasyon (175), Compose smoke (16), yayın kontrolü ve `verify.ps1`'in
tamamı **B üzerinde koşulmadı**; bunların sonuçları A içindir. Aradaki fark üç dosyadır (bölüm 6).

## Durum (kayıt A): yerel kapıların tümü `15015539…` üzerinde geçti

Bölüm 1–5'teki bütün sonuçlar A kaynak durumu içindir. Fingerprint koşulardan önce ve sonra alındı ve
aynıdır; bu doğrulama sırasında **kaynak ve betiklerde hiçbir değişiklik yapılmadı** (yalnız `docs/` ve
`artifacts/` güncellendi).

Sonuçların nasıl toplandığı (tek bir `verify.ps1` çağrısı değildir):

- İlk `./scripts/verify.ps1` koşusu (04:13) restore, build, birim ve entegrasyon kapılarını tamamladıktan sonra
  tarayıcı aşamasında, sistem belleği kritik düzeye indiği için çalışma ortamı tarafından durduruldu.
- Kalan kapılar aynı fingerprint üzerinde, `verify.ps1` içindeki komutların aynısıyla, **tek tek ve sırayla**
  koşuldu (09:43–09:54); her ağır adımdan önce boş bellek ölçüldü. Restore ve build bu oturumda yeniden koşuldu.
- Birim ve entegrasyon sonuçları ilk koşudandır (aynı fingerprint). Bu oturumda bir kez daha koşulmak istendi;
  smoke sonrası boş bellek 1,4 GB olduğu için başlatılmadı (aşağıda "Bellek").
- Test kapsamı, assertion'lar ve kritik kontroller azaltılmadı; tarayıcı testleri zaten tek koleksiyonda sıralı
  koşar.

## 1. Kapılar

| # | Kapı | Sonuç (fingerprint `15015539…`) |
|---|---|---|
| 1 | Kilitli restore + Release build + birim + gerçek PostgreSQL entegrasyon | **Geçti.** restore exit 0 · build exit 0, 0 uyarı / 0 hata (uyarılar hata sayılır) · Unit 62 / 62, skip 0 · Integration 175 / 175, skip 0 |
| 2 | UI typecheck / lint / prod build / component | **Geçti.** `npm run check` exit 0 (typecheck, lint `--max-warnings 0`, script testleri 4 / 4) · yayın kontrolü exit 0 (6 uygulama `dotnet publish -c Release`; veri erişimli 4 uygulamada EF Core 10.0.12) · sunucuda render (`UiRenderTests`, 3 test) entegrasyon içinde |
| 3 | Protokol HTTP testleri (discovery / JWKS, PKCE / kod tekrar, scope / audience / issuer, UserInfo, refresh / revoke / client auth / hatalar) | **Geçti** (entegrasyon 175 içinde; `Category=Protocol` ve `Security` testleri) |
| 4 | Gerçek tarayıcı senaryoları (kurulu Chrome, headless) | **Geçti.** 13 / 13, skip 0 (tek süreçte tam paket; ayrıca sınıf sınıf 3 + 3 + 4 + 3) |
| 5 | Anahtar rotasyonu / overlap / özel anahtar taraması / yeniden başlatma kalıcılığı | **Geçti.** Rotasyon, overlap, emeklilik, acil iptal, süreç içi yeniden başlatma: entegrasyon `Keys_*`, `Outage_*` · kaynak taraması: `scan.ps1` · imaj katmanı taraması (+ pozitif kontrol) ve Compose yeniden başlatma kalıcılığı: smoke |
| 6 | Migration: model / boş / önceki aşama verisiyle yükseltme / idempotent script | **Geçti** (`Migration_ModelHasNoPendingChanges_AndReapplyingIsANoOp`, `MigrationUpgradeTests` 2 test; boş başlatma ayrıca smoke `up`) |
| 7 | Compose HTTPS smoke: yeniden başlatma + DB / OP kesinti ve kurtarma | **Geçti.** `up` 8 / 8, `restarted` 3 / 3, `db-down` 2 / 2, `db-recovered` 1 / 1, `op-down` 1 / 1, `op-recovered` 1 / 1 (toplam 16 / 16); temizlik tamam |
| 8 | UI üç genişlik inceleme + axe / klavye | **Geçti (otomatik kısım).** axe 0 ihlal ve yatay taşma yok (29 ekran × 360 / 768 / 1440), klavye senaryosu, koyu tema / azaltılmış hareket: E2E içinde. 88 ekran görüntüsü yeniden üretildi; bu koşuda yalnız 9'u gözle incelendi (hepsinin gözle incelemesi daha önceki bir kaynak durumunda yapılmıştı, bu fingerprint için tekrarlanmadı). Bir kozmetik gözlem aşağıda. Ekran okuyucu ile elle test yapılmadı |
| 9 | Sır / yazarlık / bağımlılık bulguları; kısıtlı runtime / non-root / PII-güvenli log | **Geçti.** `scan.ps1` (çevrimiçi) 14 kontrol ok, 0 fail, 0 skip · DB rolleri ve log / audit PII testleri entegrasyon içinde · non-root, salt-okunur kök, yetkisiz konteyner ve konteyner log taraması smoke içinde |
| 10 | Uzak CI | **Koşulmadı** (push yetkisi yok; yerel koşu uzak CI sonucu sayılmaz) |

## 2. Komutlar, çıkış kodları, sayılar

| Komut | Saat | Exit | Toplam | Geçen | Kalan | Skip | Süre |
|---|---|---|---|---|---|---|---|
| `dotnet restore Halka.slnx --locked-mode` | 09:43 | 0 | — | — | — | — | < 10 sn |
| `dotnet build Halka.slnx -c Release --no-restore -v q` | 09:43 | 0 | — | — | — | — | 3 sn (artımlı), 0 uyarı / 0 hata |
| `./scripts/test.ps1 -Project Unit -Configuration Release -NoBuild` | 04:13 | 0 | 62 | 62 | 0 | 0 | 7 sn |
| `./scripts/test.ps1 -Project Integration -Configuration Release -NoBuild` | 04:14 | 0 | 175 | 175 | 0 | 0 | 65 sn |
| `npm run check` (`src/Halka.Iam/ui-tooling`) | 09:43 | 0 | 4 | 4 | 0 | 0 | 2 sn |
| Yayın kontrolü (`verify.ps1` içindeki adımlar: 6 × `dotnet publish … -c Release --no-restore -p:UseAppHost=false` + `deps.json` sürüm denetimi) | 09:44 | 0 | 6 uygulama | 6 | 0 | — | 8 sn |
| `./scripts/test.ps1 -Project E2E -Configuration Release -NoBuild -Filter '--filter-class','*SsoBrowserTests'` | 09:44 | 0 | 3 | 3 | 0 | 0 | 20 sn |
| aynı, `*MfaAndAdminBrowserTests` | 09:45 | 0 | 3 | 3 | 0 | 0 | 16 sn |
| aynı, `*RevocationAndLifecycleBrowserTests` | 09:45 | 0 | 4 | 4 | 0 | 0 | 21 sn |
| aynı, `*AccessibilityAndLayoutTests` | 09:46 | 0 | 3 | 3 | 0 | 0 | 64 sn |
| `./scripts/test.ps1 -Project E2E -Configuration Release -NoBuild` (tam paket, tek süreç) | 09:47 | 0 | 13 | 13 | 0 | 0 | 82 sn |
| `./scripts/smoke.ps1` | 09:49 | 0 | 16 (6 faz) | 16 | 0 | 0 | 234 sn |
| `./scripts/scan.ps1` (çevrimiçi; NuGet `--vulnerable --include-transitive`, `npm audit`) | 09:53 | 0 | 14 kontrol | 14 | 0 | 0 | 28 sn |
| `./scripts/source-fingerprint.ps1` (başta ve sonda) | 09:42 / 09:54 | 0 | — | — | — | — | aynı değer |

Yayın kontrolü yalnız yerel `dotnet publish` çıktısını denetler ve çıktıyı siler; **hiçbir dağıtım yapılmadı**.

Ham loglar: `artifacts/verification/raw/` (git dışı; bu oturumun dosyaları `stage10-*.log`, `smoke-*.log`).
Maskeli özet: `artifacts/verification/verify-summary.txt`. Ekran görüntüleri:
`artifacts/verification/screenshots/` (88 dosya).

### Bellek

Makinede 16 GB bellek var; komşu ürünlerin konteynerleri ve kullanıcının tarayıcısı çalışırken koşuldu, bunlara
dokunulmadı. Ölçülen en düşük boş fiziksel bellek: tarayıcı testlerinde 1,7 GB, smoke'un imaj derleme adımında
**0,4 GB**. Smoke sonrası WSL sanal makinesi belleği bir süre elinde tuttuğu için boş bellek 1,0–1,4 GB'a indi;
bu yüzden birim / entegrasyonun bu oturumdaki ikinci koşusu başlatılmadı ve tekrar denenmedi. `verify.ps1`'in tek
çağrıda baştan sona koşması bu makinede bellek açısından sınırdadır; daha fazla boş bellekle yeniden koşulabilir.

### Ekran görüntülerinde maske

`iam-mfa-enroll-{360,768,1440}.png` yeniden üretildi; QR kodu ve kurulum anahtarı düz renkle kapalıdır (gözle
doğrulandı). Kurtarma kodlarını veya yeni istemci secret'ını gösteren bir ekranın görüntüsü alınmaz; alınsaydı
aynı maske uygulanırdı. Loglarda ve `artifacts/verification` altında taşıyıcı token, `client_secret`, parola,
`otpauth://` veya özel anahtar kalıbı arandı: eşleşme yok. Görüntülerdeki hesaplar test çalıştırmasının ürettiği
`@example.test` adresleridir; anahtar ekranında yalnız açık anahtar kimlikleri (`kid`) görünür.

## 3. Gerçekten doğrulananlar

Entegrasyon (gerçek HTTPS host'ları + gerçek PostgreSQL, kısıtlı runtime rolü):

- **SSO:** Pano'da giriş → Rapor'da kimlik bilgisiz SSO, Rapor'un consent'i ayrıca; `prompt=none / login`,
  `max_age`, `auth_time`; gerçek ASP.NET OIDC istemcisiyle state / nonce / ID token saldırıları.
- **MFA:** TOTP kaydı, saat kayması sınırı, aynı kodun eşzamanlı tek kabulü, kurtarma kodları, challenge süresi ve
  deneme sınırı, yönetici zorunluluğu, step-up.
- **İptal:** refresh rotasyonu ve tekrar kullanımda aile + grant iptali; grant / oturum / kullanıcı / istemci
  iptalinin API'de bir sonraki istekte etkisi; global çıkıştan sonra kopyalanmış cookie reddi; anahtar acil iptali.
- **Kesinti:** sağlayıcı ve sağlayıcı veritabanı kesintisinde fail-closed 503 ve aynı oturum / token'larla kurtarma.

Gerçek Chrome (13 senaryo): Pano'da giriş → API → Rapor'da SSO; consent reddi; MFA'lı giriş → hassas API → Rapor
SSO ve taze girişte iki faktörün yeniden istenmesi; yöneticinin MFA kaydı, kod ve kurtarma koduyla girişi,
step-up; sağlayıcıdaki iptalin iki uygulamada ve kopyalanmış cookie'lerde görülmesi; istemciyi devre dışı bırakma
/ açma, makine istemcisi kaydı ve secret rotasyonu; normal kullanıcının yönetim alanına erişememesi; başka
kullanıcının oturumunu API veya değiştirilmiş formla sonlandıramama (IDOR); açık yönlendirme ve siteler arası
consent POST'unun reddi; axe / reflow / klavye / koyu tema.

Compose konteynerleri (16 test): HTTPS ve cookie özellikleri, konteynerler arası SSO, makine istemcisi, non-root
ve salt-okunur konteynerler, imaj ve log taraması, yeniden başlatmada veri / anahtar / oturum kalıcılığı,
veritabanı ve sağlayıcı kesintisinde 503 ve kurtarma.

## 4. Bu aşamada bulunan hatalar: fail → kök neden → düzeltme → sonuç

| Belirti | Kök neden | Sınıf | Düzeltme | Sonuç |
|---|---|---|---|---|
| Smoke: Pano / Rapor konteynerleri açılmıyor (`FileNotFoundException: Microsoft.EntityFrameworkCore 10.0.12`) | Kitaplık 10.0.12'ye derleniyor, uygulama grafiği 10.0.4 çözüyordu; testler IAM üzerinden doğru sürümü aldığı için görmedi | Uygulama / paket | `Microsoft.EntityFrameworkCore.Relational` açık referans; lock dosyaları yenilendi; `verify.ps1` yayın kontrolü | Smoke `up` 8 / 8; yayın kontrolü geçti |
| Smoke `db-down`: Pano 500 | Uygulamanın kendi deposunun ulaşılamaması ele alınmıyordu | Uygulama | 503 ara katmanı depo hatalarını da kapsar; cookie korunur | `db-down` 2 / 2 |
| Smoke `op-recovered`: Rapor'a ilk giriş 503 | Önceki DB yeniden başlatmasından kalan ölü havuz bağlantısı (`57P01`) | Uygulama | Demo istemcide geçici hata yeniden denemesi; kesinti fark edildiğinde havuz temizliği; boşta bağlantı ömrü 60 sn | `op-recovered` 1 / 1 |
| DB kesintisinde `/connect/token` HTML döndürüyor | İstisna ara katmanı istek yolunu değiştirdiği için yol kontrolü eşleşmiyordu | Uygulama | Özgün yol `IExceptionHandlerPathFeature` üzerinden | `DatabaseDown_...` geçti |
| Outbox / retention testlerinde zaman eşitliği | PostgreSQL mikrosaniye hassasiyeti | Test beklentisi | Saklanan hassasiyete yuvarlama | Geçti |
| `scan.ps1`: pozitif kontrol hiçbir şey bulmuyor; port kontrolü 4 yerine 2 sayıyor | Hariç tutma kuralı örnek dizini de eliyordu; tr-TR yerel ayarında büyük-küçük harf duyarsız eşleşme `I` / `i` ayrımı | Tarama betiği | Göreli yol üzerinden hariç tutma; kültürden bağımsız eşleşme; büyük harfli pozitif kontrol | 14 / 14 |
| Ekran görüntüsünde test hesabının TOTP anahtarı | Maske yoktu | Test altyapısı | Maske eklendi; eski görüntüler silindi | Maskeli olarak yeniden üretildi ve gözle doğrulandı |
| `verify.ps1` tarayıcı aşamasında kesildi | Sistem belleği kritik düzeyde; ortam arka plan komutunu durdurdu | Ortam | Kalan kapılar aynı fingerprint üzerinde tek tek, bellek ölçülerek koşuldu | Hepsi geçti |

Kayıt A sırasında görülen ve o doğrulamada düzeltilmeyen iki kozmetik kusur (ikisi de bölüm 6'da düzeltildi):

- `pano-workspace-360.png`: not tablosunun başlığı ("Notes returned by the API") 360 px genişlikte dar bir sütuna
  sıkışıp dört satıra bölünüyordu. İçerik okunuyordu, yatay taşma yoktu.
- `verify.ps1` log dosya adını tr-TR yerel ayarında `verify-tests-ntegration.log` olarak üretiyordu.

## 5. Koşulmayanlar

Uzak CI, OpenID Foundation uyumluluk paketi, yük ve çok-instance testleri, elle ekran okuyucu testi, sızma testi,
Linux / macOS üzerinde `local-stack.sh`, `verify.ps1`'in tek çağrıda baştan sona koşusu (bellek). Ayrıntı:
`docs/known-limitations.md`.

## 6. Kayıt B — iki kozmetik düzeltme (2026-10-11, 14:25–14:38)

**Fingerprint:** önce `sha256:15015539…e12c9`, sonra
`sha256:47adc621657715d0d0a98ecad97e0a86f416a65a208a90a8f4a56e13a135573d` (248 dosya). Backend ve protokol
kaynakları değişmedi; bu yüzden birim, tam entegrasyon, Compose smoke, yayın kontrolü ve `verify.ps1` paketi
yeniden koşulmadı.

### Değişen dosyalar

| Dosya | Değişiklik | Gerekçe |
|---|---|---|
| `src/Halka.Iam/wwwroot/site.css` | 720 px altındaki blok tablo düzeninde görünür `caption` da blok yapılır; hücrelerle aynı yatay boşluk ve alt çizgi | Kök neden: tablo `display: block` olunca `table-caption` kalan başlık en uzun kelimesinin genişliğine daralıyordu. Kural ortak olduğu için aynı kusur Halka ID'nin dar ekrandaki bütün başlıklı tablolarında vardı (kısa başlıklarda az göze çarpıyordu); düzeltme hepsini kapsar. Renk, yazı tipi, masaüstü görünümü ve `visually-hidden` başlıklar değişmedi; içerik gizlenmedi |
| `tests/Halka.E2E/AccessibilityAndLayoutTests.cs` | (1) Her ekranda, her genişlikte: görünür tablo başlığı tablosunun en az %90'ı kadar geniş olmalı. (2) Pano çalışma alanı kontrolünden önce bir not eklenir ve başlığın göründüğü doğrulanır | (1) Regresyon koruması; var olan kontroller kaldırılmadı. (2) Tablo yalnız not varsa çizilir; önceden bu, aynı koleksiyondaki başka bir testin daha önce not yazmış olmasına bağlıydı (sınıf tek başına koşulunca Pano başlığı hiç sınanmıyordu) |
| `scripts/verify.ps1` | Log adı `Get-GateLogName` işlevine alındı; `-replace` yerine `-creplace` | Büyük-küçük harf duyarsız eşleşme geçerli kültürü izler; tr-TR'de `I`, `[a-zA-Z]` dışında kalıyordu. Kapı listesi, sırası, komutları, özet ve exit-code davranışı değişmedi |

### Komutlar ve sonuçlar (hepsi `47adc621…` üzerinde, aksi yazılmadıkça)

| Kontrol | Komut | Exit | Toplam | Geçen | Kalan | Skip |
|---|---|---|---|---|---|---|
| Negatif kontrol (yeni başlık kontrolü var, CSS düzeltmesi **yok**; ara durum) | `./scripts/test.ps1 -Project E2E -Configuration Release -Filter '--filter-method','*A11y_KeyScreens_HaveNoAxeViolations_AndReflow_AtThreeWidths'` | 2 (beklenen) | 1 | 0 | 1 | 0 |
| Erişilebilirlik / yerleşim sınıfı (axe, yatay taşma, başlık genişliği: 29 ekran × 360 / 768 / 1440; klavye; koyu tema) | `./scripts/test.ps1 -Project E2E -Configuration Release -Filter '--filter-class','*AccessibilityAndLayoutTests'` | 0 | 3 | 3 | 0 | 0 |
| Tam tarayıcı paketi (kurulu Chrome, headless) | `./scripts/test.ps1 -Project E2E -Configuration Release` | 0 | 13 | 13 | 0 | 0 |
| Release build (uyarılar hata sayılır) | `dotnet build Halka.slnx -c Release --no-restore -v q` | 0 | — | 0 uyarı / 0 hata | — | — |
| UI araçları (typecheck, lint, script testleri) | `npm run check` (`src/Halka.Iam/ui-tooling`) | 0 | 4 | 4 | 0 | 0 |
| Sunucuda render (UI) | `./scripts/test.ps1 -Project Integration -Configuration Release -NoBuild -Filter '--filter-class','*UiRenderTests'` | 0 | 3 | 3 | 0 | 0 |
| Stil dosyasının sunumu ve güvenlik başlıkları | aynı, `-Filter '--filter-method','*Health_OpenApi_AndSecurityHeaders_ArePresent'` | 0 | 1 | 1 | 0 | 0 |
| Log adları, tr-TR | `powershell -NoProfile -File check-gate-log-names.ps1 -Culture tr-TR` | 0 | 9 ad | 9 | 0 | — |
| Log adları, en-US | aynı, `-Culture en-US` | 0 | 9 ad | 9 | 0 | — |
| `Invoke-Gate` davranışı (sahte kapılarla) | `powershell -NoProfile -File check-invoke-gate.ps1` | 0 | 5 kontrol | 5 | 0 | — |
| Tarama (çevrimiçi) | `./scripts/scan.ps1` | 0 | 14 kontrol | 14 | 0 | 0 |

- Negatif kontrolün hata iletisi: `iam-sessions @ 360px has a squeezed table caption: Active central sessions`
  (test, ilk bulduğu ekranda durur). Düzeltmeden sonra aynı test geçti.
- Tam tarayıcı paketinin yeniden koşulma gerekçesi: stil dosyası bütün ekranlarda ortaktır ve değişen test, aynı
  koleksiyondaki diğer testlerle paylaşılan yığına not yazar.
- **Betik testleri hakkında:** depoda PowerShell betikleri için test altyapısı yoktur ve bu görevde eklenmedi. Log
  adı kontrolü depo dışı iki küçük betikle yapıldı (kopyaları ham logların yanında:
  `artifacts/verification/raw/check-*.ps1`). İkisi de `verify.ps1`'i ayrıştırıp **gerçek** `Get-GateLogName` ve
  `Invoke-Gate` işlevlerini ve betikteki kapı adlarını kullanır; kültür ayrı süreçte ayarlanır ve doğrulanır.
  Beklenen adlar: `verify-restore-locked.log`, `verify-build-release.log`, `verify-tests-unit.log`,
  `verify-tests-integration.log`, `verify-tests-e2e.log`, `verify-ui-tooling-typecheck-lint-script-tests.log`,
  `verify-publish-release.log`, `verify-scan-secrets-authorship-dependencies.log`, `verify-smoke-compose.log`.
  Eski ifade tr-TR'de bunlardan ikisini bozuyordu (`verify-tests-ntegration.log`,
  `verify-u-tooling-typecheck-lint-script-tests.log`), en-US'te hiçbirini. `Invoke-Gate` kontrolü: doğru dosya
  adı, log içeriği, exit 0 → başarılı, exit 3 → koşu başarısız işaretlenir, satır sırası çağrı sırasıdır.
- Makinede yalnız Windows PowerShell 5.1 kuruludur (varsayılan kültür tr-TR); PowerShell 7 ile denenmedi.
  `verify.ps1`'in kendisi baştan sona koşulmadı.

### Gerçek tarayıcıda üç genişlik

88 ekran görüntüsü `47adc621…` üzerinde yeniden üretildi. Gözle incelenenler: `pano-workspace-360 / 768 / 1440`
(başlık tek satır ve okunaklı; 768 ve 1440'ta görünüm öncekiyle aynı), `iam-sessions-360`,
`iam-connected-apps-360` (aynı düzeltme), `iam-mfa-enroll-768` (QR ve kurulum anahtarı maskeli).
`artifacts/verification` altında token / `client_secret` / parola / `otpauth` / özel anahtar kalıbı: eşleşme yok.

### Bellek

En düşük boş fiziksel bellek: derleme + erişilebilirlik sınıfı 0,35 GB, tam tarayıcı paketi 0,8 GB. Komşu
ürünlerin konteynerlerine ve süreçlerine dokunulmadı; geride test konteyneri kalmadı.

### Kayıt B'nin sınırları

- Birim (62), tam entegrasyon (175), Compose smoke (16), yayın kontrolü ve `verify.ps1` paketi `47adc621…`
  üzerinde koşulmadı. Değişen ürün dosyası yalnız stil dosyasıdır; smoke imajları bu stil dosyasıyla yeniden
  derlenmedi.
- Başlık genişliği kontrolü erişilebilirlik testinin gezdiği 29 ekranı kapsar; başlıklı tablosu olup bu testte
  gezilmeyen ekranlar (ör. `/manage/activity`) aynı ortak kuralı kullanır ama ayrıca ölçülmedi.
- Uzak CI, farklı tarayıcı, ekran okuyucu: koşulmadı (kapsam dışı).
