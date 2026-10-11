# 09 — Test ve Doğrulama Planı

## 1. Katmanlar

| Katman | Proje | Ortam | Ne kanıtlar |
|---|---|---|---|
| Unit | `Halka.UnitTests` | Saf bellek, `FakeTimeProvider` | Durum makineleri, doğrulayıcılar, hash/kod biçimleri, URI kuralları, anahtar durum geçişleri |
| Integration | `Halka.IntegrationTests` | Testcontainers PostgreSQL 17 + gerçek Kestrel HTTPS host'ları (IAM, Pano, Rapor, API) aynı süreçte | Gerçek HTTP protokol testleri, DB rolleri/grant'leri, atomik guard'lar, transaction'lar, yarışlar |
| E2E | `Halka.E2E` | Aynı harness + kurulu Chrome (Playwright, `channel=chrome`) | Tarayıcı akışları, cookie/SameSite, UI, axe/klavye |
| UI araçları | `src/Halka.Iam/ui-tooling` | Node | JS typecheck (`tsc --checkJs`), ESLint, `node --test` |
| Compose smoke | `scripts/smoke.ps1` | Ayrı, atılabilir Compose projesi (`halka-smoke`) | Boş init/up, container DNS, restart kalıcılığı, DB/OP kesinti/iyileşme, non-root, image/log taraması |

Kütüphane API'siyle doğrudan token üretmek gerçek roundtrip'in yerine geçmez: protokol testleri gerçek HTTP ile `/connect/*` endpoint'lerine gider; istemci tarafı gerçek ASP.NET Core OIDC handler'ıdır. İstemci doğrulama testlerinde (tampered ID token, yanlış issuer/audience, eksik state/nonce) yalnız taşıma katmanı araya girer; doğrulama kütüphanesi baypas edilmez.

## 2. Güvenli test ortamı

- Veritabanı: Testcontainers'ın oluşturduğu atılabilir PostgreSQL. Dev/paylaşılan/başka proje DB'sine migration/seed/cleanup yapılmaz.
- **Test guard** (`TestDatabaseGuard`): yazma yapan her harness adımından önce üç koşul: (1) açık opt-in (`HALKA_TEST_ALLOW_DB_WRITES=1`, harness tarafından süreç içinde ayarlanır), (2) hedef DB'de bu koşunun sahiplik işareti (`__halka_test_owner.run_id`), (3) sunucu kimliği (`system_identifier` + port) container açılışında kaydedilenle aynı. Yalnız isim önekine güvenilmez. Yanlış hedefte sıfır yazma testi vardır.
- Zaman: tüm host'lar ortak `FakeTimeProvider` kullanır; süre dolumu testleri saati ilerletir. Yarış testleri bariyer/kilitle eşzamanlı başlatılır ve **değişmez** (tam bir başarı, nihai DB durumu) doğrulanır; rastgele `sleep` kanıt sayılmaz.
- Sırlar: test TOTP secret'ları ve parolalar yalnız süreç içinde üretilir; log/artefakta yazılmaz. Seed demo kullanıcı sırları test fixture'larından farklıdır.
- Tarayıcı TLS: Chrome yalnız test CA/leaf SPKI özetlerine güvenir (`--ignore-certificate-errors-spki-list`); genel sertifika hatası yok sayma kullanılmaz.

## 3. Test envanteri (isim önekleri → kapı)

| Önek | Aşama | Tür |
|---|---|---|
| `Login_*`, `Signup_*`, `Session_*`, `Csrf_*`, `MailSink_*`, `DbRoles_*`, `TestGuard_*` | 1 | Integration |
| `Discovery_*`, `Jwks_*`, `Code_*`, `Redirect_*`, `Client_*`, `Api_*` | 3 | Integration (protokol) |
| `Consent_*`, `Sso_*`, `Prompt_*`, `UserInfo_*` | 4 | Integration + E2E |
| `Totp_*`, `Recovery_*`, `Mfa_*`, `StepUp_*`, `Admin_RequiresMfa*` | 5 | Unit + Integration + E2E |
| `Refresh_*`, `Revoke_*`, `GlobalLogout_*`, `EndSession_*`, `Outage_*` | 6 | Integration + E2E |
| `Machine_*`, `ClientSecret_*`, `Keys_*` | 7 | Integration |
| `Admin_*`, `LastAdmin_*`, `Idor_*`, `Ui_*`, `A11y_*` | 8 | Integration + E2E |
| `Reset_*`, `Outbox_*`, `RateLimit_*`, `Logs_*`, `Metrics_*`, `Retention_*` | 9 | Integration |
| `Migration_*` | 1–10 | Integration |

## 4. Migration doğrulaması

1. `Migration_ModelHasNoPendingChanges_AndReapplyingIsANoOp` — snapshot ile model uyumu; boş veritabanına uygulanmış şemanın yeniden uygulanması değişiklik yapmaz (her test yığını boş veritabanına tüm migration'ları uygular).
2. `Upgrade_FromTheStage1AndStage3Schemas_KeepsExistingData_AndTheResultIsUsable` — Aşama 1 şeması + o sürümün kolonlarıyla yazılmış sentetik veri → Aşama 3 → son şema; veri korunur ve güncel kodla, kısıtlı runtime rolü üzerinden kullanılabilir.
3. `IdempotentScript_AppliedTwice_ProducesTheSameSchemaAsTheMigrator` — üretilen idempotent SQL script'i boş bir veritabanına iki kez uygulanır; kolon, kısıt ve indeksler migrator'ın ürettiği şemayla birebir aynıdır.

## 5. Final kapıları (Aşama 10)

| # | Kapı | Komut (proje kökünden) |
|---|---|---|
| 1 | Kilitli restore + Release build + unit + integration | `dotnet restore --locked-mode`; `dotnet build -c Release --no-restore`; `dotnet test` (Unit, Integration) |
| 2 | UI typecheck/lint/prod build/component | `npm ci && npm run check` (ui-tooling); `dotnet publish` (Razor derleme); `Ui_*` render testleri |
| 3 | Protokol HTTP testleri | `dotnet test --filter Category=Protocol` |
| 4 | Gerçek tarayıcı senaryoları | `dotnet test tests/Halka.E2E` |
| 5 | Anahtar rotasyonu/overlap/private key taraması/restart kalıcılığı | `Keys_*` + smoke |
| 6 | Migration model/boş/önceki aşama/idempotent script | `Migration_*`, `MigrationUpgradeTests` |
| 7 | Compose HTTPS smoke + restart + DB/OP kesinti | `scripts/smoke.ps1` |
| 8 | UI üç genişlik elle inceleme + axe/klavye | E2E ekran görüntüleri + elle gözden geçirme notu |
| 9 | Sır/authorship/bağımlılık bulguları; kısıtlı runtime/non-root/PII-güvenli log | `scripts/scan.ps1` + `dotnet list package --vulnerable` |
| 10 | Uzak CI | Push yetkisi olmadığı için **koşulmaz**; yerel sonuç uzak sonuç sayılmaz |

Tüm kapılar tek kaynak durumunda: `./scripts/verify.ps1` (başta ve sonda kaynak fingerprint'i alır; arada kaynak değiştiyse koşu geçersizdir).

## 6. Bilinçli olarak koşulmayanlar

OIDC conformance suite (OpenID Foundation) koşulmadı → "OIDC certified / tam uyumlu" denmez. Yük testi, çok-instance testi, elle ekran okuyucu testi, formal pentest yapılmadı. Tarayıcı kapsamı yalnız Chrome'dur.

## 7. Raporlama

Her koşu için: komut, exit code, toplam/pass/fail/skip, süre, kaynak fingerprint'i (`scripts/source-fingerprint.ps1`: izlenen + izlenmeyen-ignore-dışı dosyaların SHA-256 özeti). Başarısızlıkta kök neden uygulama / test fixture / ortam olarak ayrılır ve `final-verification.md`'ye fail → kök neden → düzeltme → pass zinciri yazılır. Assertion zayıflatarak veya kritik testi atlayarak yeşil elde edilmez.
