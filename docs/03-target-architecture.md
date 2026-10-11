# 03 — Hedef Mimari

## 1. Çalışma zamanı görünümü

```
                 Tarayıcı (Chrome)
      ┌──────────────┼──────────────────┐
      ▼              ▼                  ▼
 Pano (BFF)     Halka ID (IAM)     Rapor (BFF)
 :9444          :9443              :9445
   │  ▲  token/introspect/revoke ▲   │
   │  └──────────────┬───────────┘   │
   ▼                 │               ▼
        Workspace API :9446 ──introspect──▶ Halka ID
                                │
 Machine demo ──client_credentials──▶ Halka ID ──▶ PostgreSQL (halka_iam)
 Pano/Rapor ──▶ PostgreSQL (halka_pano / halka_rapor: şifreli app oturumları)
```

Tek PostgreSQL sunucusu; üç ayrı veritabanı ve ayrı roller. Broker/cache yok.

## 2. Solution yapısı

| Proje | Tür | Sorumluluk |
|---|---|---|
| `src/Halka.Shared` | lib | Yerel CA güveni, backchannel HttpClient, secret-file okuma, Data Protection kurulumu, güvenlik header'ları, ProblemDetails |
| `src/Halka.Iam` | ASP.NET Core (Razor Pages + MVC controller) | Identity, oturum, MFA, OpenIddict server, consent, admin, audit, outbox |
| `src/Halka.DemoClient` | Razor class library | BFF altyapısı: OIDC handler ayarı, DB ticket store, refresh singleflight, oturum doğrulama, sayfalar |
| `src/Halka.Pano`, `src/Halka.Rapor` | ASP.NET Core host | İki ayrı deploy edilebilir istemci (ayrı origin, cookie, DB, client kimliği) |
| `src/Halka.WorkspaceApi` | ASP.NET Core minimal API | Resource server (OpenIddict validation + introspection) |
| `src/Halka.MachineDemo` | konsol | `client_credentials` demo |
| `src/Halka.Migrator` | konsol | Migration uygulama, runtime grant'leri, seed (migration rolüyle) |
| `tools/Halka.LocalInit` | konsol | `.local/` altına CA/TLS, parola, secret, pg init üretimi (idempotent) |
| `tests/Halka.TestKit` | lib | Testcontainers PostgreSQL, çok-host Kestrel harness, test guard, HTTP "tarayıcı" |
| `tests/Halka.UnitTests` | xUnit v3 | Saf iş kuralı/state testleri |
| `tests/Halka.IntegrationTests` | xUnit v3 | Gerçek PostgreSQL + gerçek HTTP protokol testleri |
| `tests/Halka.E2E` | xUnit v3 + Playwright | Gerçek Chrome ile uçtan uca |

## 3. IAM iç modülleri (`Halka.Iam`)

| Modül | İçerik |
|---|---|
| `Data` | `IamDbContext` (Identity + OpenIddict + ürün tabloları), migration'lar |
| `Identity` | `ApplicationUser`, parola/lockout politikası, tek kullanımlık token servisi |
| `Sessions` | Merkezi oturum servisi, cookie doğrulama (her istekte DB), step-up |
| `Mfa` | TOTP (Otp.NET) + timestep replay guard, recovery code, challenge |
| `Protocol` | OpenIddict yapılandırması, authorize/token/userinfo/endsession controller'ı, özel handler'lar, client secret manager, anahtar halkası |
| `Clients` | Client/scope kaydı, disable, secret rotation |
| `Revocation` | Tüm iptal eylemlerinin tek servisi (`RevocationService`) |
| `Admin` | Yetki politikaları, last-admin guard, yönetim işlemleri |
| `Audit` | Salt-ekleme audit yazıcı |
| `Mail` | Outbox + leased worker + private dosya sink |
| `Ops` | Health, rate limit, token pruning |

Bağımlılık yönü: Sayfalar/controller'lar → servisler → `IamDbContext`. İptal kuralları tek yerde (`RevocationService`) toplanır; sayfalar doğrudan token tablosuna dokunmaz.

## 4. Teknoloji kararları (özet; ayrıntı ADR'lerde)

| Karar | Seçim | Daha basit alternatif | Maliyet | Sınır | Değişme koşulu |
|---|---|---|---|---|---|
| Runtime | .NET 10 LTS (SDK 10.0.401) | — | — | — | LTS değişimi |
| Protokol | OpenIddict 7.7.2 (Apache-2.0) | Keycloak proxy | Pass-through controller yazımı | Back-channel logout yok | Lisans/bakım değişimi |
| Store | PostgreSQL 17 + EF Core 10 / Npgsql | SQLite | Container gerekir | Tek instance doğrulandı | — |
| UI | Razor Pages (server-rendered) + küçük vanilla JS | React SPA | Daha az etkileşim | SPA deneyimi yok | Zengin istemci ihtiyacı |
| Access token | Reference token + introspection | Self-contained JWT | İstek başına IAM çağrısı | IAM bağımlılığı | Yük/latency hedefi |
| TOTP | Otp.NET + atomik timestep guard | Identity authenticator provider | Küçük özel provider | — | — |
| Anahtarlar | DB'de Data Protection ile sarılı RSA anahtarları | PFX dosyaları | Options cache yenileme | Tek instance | HSM/KMS ihtiyacı |
| Mail | DB outbox + leased worker + dosya sink | Senkron dosya yazma | Worker karmaşıklığı | Gerçek SMTP yok | Gerçek sağlayıcı |
| Testler | xUnit v3, Testcontainers, Playwright (kurulu Chrome) | In-memory DB | Docker gerekir | — | — |

## 5. Güven sınırları ve sırlar

| Sır | Konum | Not |
|---|---|---|
| Yerel CA + TLS leaf anahtarları | `.local/tls/` | Git'te yok, image'da yok; container'a read-only mount |
| DB rol parolaları | `.local/secrets/` | Compose secret dosyası |
| Data Protection key ring | `.local/dp-keys/<app>/` | Sarmalama sertifikası `.local/dp-wrap/<app>.pfx` ile şifreli |
| İmzalama/şifreleme anahtarları | DB `protocol_keys` (DP ile sarılı) | JWKS yalnız public |
| TOTP secret | DB `user_mfa.protected_secret` (DP ile sarılı) | |
| Client secret | DB hash (OpenIddict PBKDF2) | Düz metin yalnız `.local/secrets/` (demo client'lar için) |
| Seed kullanıcı parolaları | `.local/seed/credentials.json` | |

Roller ayrıdır: TLS sertifikası ≠ token imzalama anahtarı ≠ token şifreleme anahtarı ≠ Data Protection anahtarı.
`.local/` kaybı: TOTP kayıtları ve protokol anahtarları çözülemez → yeniden `init` + kullanıcıların MFA'yı yeniden kurması gerekir (bilinen sınır).

## 6. Dağıtım (yerel Compose)

- Proje adı `halka`, portlar 9443–9446 (yalnız `127.0.0.1`); komşu ürün portlarına (8443/8643/8843) dokunulmaz.
- Servisler: `postgres`, `migrator` (tek seferlik), `iam`, `pano`, `rapor`, `workspace-api`, `machine-demo` (profil).
- Container içi DNS: her servis kendi public hostname'ini ağ alias'ı olarak taşır; issuer URL'i tarayıcıdan ve container içinden aynıdır.
- Tüm uygulama container'ları non-root, read-only root filesystem, `cap_drop: ALL`.
- `down` volume silmez; `reset` açık onay + hedef guard ister.

## 7. Gözlemlenebilirlik

- Yapılandırılmış log (JSON console); token/secret değerleri asla loglanmaz, `Authorization`/`Cookie` header'ları redakte edilir.
- Metric'ler (`System.Diagnostics.Metrics`): düşük kardinalite; user/client/token id label değildir.
- Health: `/health/live` (process), `/health/ready` (DB + anahtar halkası).
- Her istekte correlation id (W3C trace id) audit kaydına yazılır.

## 8. Ölçek sınırı

Tek IAM instance'ı doğrulanmıştır. Çok instance için gerekenler (uygulanmadı): anahtar halkası değişikliklerinin instance'lar arası yayılımı, dağıtık rate limit, BFF refresh kilidinin DB tabanlı olması.
