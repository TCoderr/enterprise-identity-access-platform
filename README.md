# Halka ID — Enterprise Identity & Access Management Platform

**Yazar / sahip:** TCoderr

Halka ID; merkezi kimlik sağlayıcı (OpenID Provider), OAuth 2.0 / OpenID Connect yetkilendirme sunucusu, iki
demo uygulama arasında tek oturum açma (SSO), çok faktörlü doğrulama (TOTP + kurtarma kodları), uygulama (client)
kaydı, kullanıcı onayı (consent), oturum / grant / token iptali ve yönetim arayüzünü tek bir yerel yığında
gösteren bir C# / .NET 10 portföy projesidir.

> **Durum ve dürüst sınır.** Bu bir portföy / referans uygulamasıdır. Yerelde uçtan uca doğrulanmıştır
> (`docs/final-verification.md`), ancak üretim ortamında çalıştırılmamış, bağımsız güvenlik denetiminden
> geçmemiş ve OpenID Foundation uyumluluk (conformance) paketiyle sınanmamıştır; "sertifikalı" veya "üretime
> hazır" iddiası yoktur. Bilinen sınırlar: `docs/known-limitations.md`.

## Bileşenler

| Bileşen | Adres (yerel) | Görev |
|---|---|---|
| **Halka ID** (`src/Halka.Iam`) | `https://id.halka.localhost:9443` | Kimlik sağlayıcı, hesap ve yönetim arayüzü, protokol uç noktaları |
| **Pano** (`src/Halka.Pano`) | `https://pano.localhost:9444` | Demo istemci 1 (sunucu taraflı oturum, BFF) |
| **Rapor** (`src/Halka.Rapor`) | `https://rapor.localhost:9445` | Demo istemci 2 (farklı site; SSO kanıtı) |
| **Workspace API** (`src/Halka.WorkspaceApi`) | `https://workspace-api.localhost:9446` | Korunan kaynak API (introspection) |
| **Machine demo** (`src/Halka.MachineDemo`) | — | `client_credentials` ile API çağıran konsol istemcisi |
| **Migrator** (`src/Halka.Migrator`) | — | Şema, kısıtlı DB rolleri, seed (tek seferlik konteyner) |
| PostgreSQL 17 | yalnız iç ağ | Kimlik, oturum, grant, token, denetim kaydı |

Teknoloji: ASP.NET Core 10 (Razor Pages), ASP.NET Core Identity, EF Core 10 + Npgsql, **OpenIddict 7.7.2**
(protokol, token üretimi ve doğrulaması), Otp.NET (TOTP), Docker Compose. Protokol veya kripto elle yazılmamıştır.

## Ön koşullar

- .NET SDK 10.0.401+ (`global.json`)
- Docker Engine + Compose v2
- Testler için: Google Chrome (tarayıcı testleri kurulu Chrome'u kullanır), Node.js 24 (yalnız UI araçları)
- Boş portlar: 9443–9446 (geliştirme), 9453–9456 (smoke testi)

Makinede genel bir ayar değiştirilmez: `hosts` dosyası, sistem sertifika deposu ve genel araç kurulumu
gerekmez. `*.localhost` adlarını tarayıcılar kendiliğinden loopback'e çözer.

## Hızlı başlangıç

PowerShell (Windows):

```powershell
cd enterprise-identity-access-platform
./scripts/local-stack.ps1 up        # ilk seferde .local/ üretir, imajları derler, yığını başlatır
./scripts/local-stack.ps1 status
./scripts/local-stack.ps1 machine   # makine istemcisi demosu (client_credentials → API)
./scripts/local-stack.ps1 logs -Service iam
./scripts/local-stack.ps1 down      # konteynerleri kaldırır; veri, anahtarlar ve .local/ kalır
```

Bash (Linux / macOS):

```bash
cd enterprise-identity-access-platform
./scripts/local-stack.sh up
./scripts/local-stack.sh status
./scripts/local-stack.sh machine
./scripts/local-stack.sh logs --service iam
./scripts/local-stack.sh down
```

`reset` yıkıcıdır (veritabanı volume'u ve `.local/` silinir) ve açık onay ister:
`./scripts/local-stack.ps1 reset -ConfirmProject halka` / `./scripts/local-stack.sh reset --confirm-project halka`.

### Sertifika uyarısı

`init`, yalnız bu proje için bir yerel CA ve sunucu sertifikaları üretir (`.local/tls/`). Sistem deposuna
eklenmez; bu yüzden tarayıcı ilk açılışta uyarı gösterir. İki seçenek: uyarıyı bu yerel adresler için geçmek ya da
`.local/tls/ca.crt` dosyasını **yalnız kendi tarayıcı profilinize** güvenilir kök olarak eklemek (kendi
kararınız; proje bunu sizin yerinize yapmaz).

### Anahtarlar ve yeniden başlatma

Dört ayrı anahtar türü vardır ve birbirinin yerine kullanılmaz: TLS sertifikaları (`.local/tls/`), token imzalama
ve şifreleme anahtarları (veritabanında, Data Protection ile sarılı), Data Protection anahtarları
(`.local/dp-keys/`, ayrı bir sarma sertifikasıyla korunur) ve client secret'ları (`.local/secrets/`).

- `down` / `up` ve konteyner yeniden başlatmaları hiçbir anahtarı değiştirmez: issuer adresi, imza anahtarı
  (`kid`), oturumlar ve token'lar aynı kalır (smoke testiyle doğrulanır).
- `reset` veya `.local/` dizinini silmek **her şeyi yeniden üretir**: tüm oturumlar, token'lar, MFA kayıtları,
  demo parolaları ve client secret'ları geçersiz olur; tarayıcıya eklenmiş yerel CA da değişir.
- Port tabanını (`-PortBase`) değiştirmek issuer adresini değiştirir; mevcut bir kurulumda yapılmamalıdır
  (önce `reset`).

## Demo hesapları ve istemciler

Parolalar ve client secret'lar depoda **yoktur**; `init` her kurulum için rastgele üretir.

| Hesap | Rol | Parola |
|---|---|---|
| `admin@halka.test` | PlatformAdmin | `.local/seed/credentials.json` |
| `secadmin@halka.test` | SecurityAdmin | `.local/seed/credentials.json` |
| `appadmin@halka.test` | ApplicationAdmin | `.local/seed/credentials.json` |
| `alice@halka.test` | User | `.local/seed/credentials.json` |

| Client | Tür | Akış | Secret |
|---|---|---|---|
| `pano-web` | web (confidential) | authorization code + PKCE, refresh | `.local/secrets/client-pano` |
| `rapor-web` | web (confidential) | authorization code + PKCE, refresh | `.local/secrets/client-rapor` |
| `workspace-api` | resource | yalnız introspection | `.local/secrets/client-workspace-api` |
| `ops-machine` | machine | client credentials | `.local/secrets/client-ops-machine` |

Diğer özel yollar: demo e-postaları `.local/mail-sink/` (gerçek e-posta gönderilmez), Data Protection anahtarları
`.local/dp-keys/`, TLS anahtarları `.local/tls/`. `.local/` git tarafından yok sayılır ve imajlara kopyalanmaz.

## Deneme senaryosu

1. `https://pano.localhost:9444` → **Sign in** → Halka ID'de `alice@halka.test` ile giriş → onay ekranı → Pano.
2. **Workspace** sayfasında API'yi çağırın (Pano erişim token'ını tarayıcıya vermez; çağrıyı sunucudan yapar).
3. `https://rapor.localhost:9445` → **Sign in**: parola sorulmaz (SSO), yalnız Rapor için onay istenir.
4. `https://id.halka.localhost:9443/manage`: oturumlar, bağlı uygulamalar, MFA kaydı (QR + kurtarma kodları).
5. Bir oturumu veya uygulama iznini iptal edin; Pano / Rapor bir sonraki istekte oturumu düşürür.
6. `admin@halka.test` ile giriş → MFA kaydı zorunludur → `/admin`: kullanıcılar, oturumlar, grant'ler, client
   kaydı (secret bir kez gösterilir), secret rotasyonu, imza anahtarı rotasyonu, denetim kaydı.
7. Yeni hesap: **Create account** → onay bağlantısı `.local/mail-sink/` altındaki JSON dosyasındadır.

## Test ve doğrulama

```powershell
dotnet restore Halka.slnx --locked-mode
./scripts/test.ps1 -Project Unit           # birim testleri
./scripts/test.ps1 -Project Integration    # gerçek Kestrel + Testcontainers PostgreSQL, protokol/güvenlik
./scripts/test.ps1 -Project E2E            # kurulu Chrome ile gerçek tarayıcı, axe erişilebilirlik
./scripts/smoke.ps1                        # ayrı Compose projesinde HTTPS, yeniden başlatma, DB/OP kesintisi
./scripts/scan.ps1                         # sır / yazarlık / bağımlılık / konteyner taraması
./scripts/verify.ps1                       # yukarıdakilerin tümü, tek kaynak durumu üzerinde
```

Linux / CI eşdeğeri (`.github/workflows/ci.yml` ile aynı adımlar; bu depo uzak bir CI'da **çalıştırılmamıştır**):

```bash
dotnet restore Halka.slnx --locked-mode
dotnet build Halka.slnx -c Release --no-restore
dotnet test --project tests/Halka.UnitTests -c Release --no-build
dotnet test --project tests/Halka.IntegrationTests -c Release --no-build
dotnet test --project tests/Halka.E2E -c Release --no-build
(cd src/Halka.Iam/ui-tooling && npm ci && npm run check)
```

Testler yalnız kendi oluşturdukları atılabilir veritabanlarına yazar (açık izin + sahiplik işareti + sunucu
kimliği kontrolü); geliştirme yığınına veya başka bir projenin veritabanına dokunmaz.

## Depo yapısı

```
src/Halka.Iam            kimlik sağlayıcı (Razor Pages, protokol, oturum, MFA, yönetim)
src/Halka.DemoClient     Pano ve Rapor'un ortak istemci kitaplığı (OIDC, sunucu taraflı oturum)
src/Halka.Pano, Rapor    demo istemciler
src/Halka.WorkspaceApi   korunan API
src/Halka.MachineDemo    makine istemcisi
src/Halka.Migrator       şema / rol / seed
src/Halka.Shared         ortak altyapı (sır dosyaları, backchannel, güvenlik başlıkları, log)
tools/Halka.LocalInit    .local/ üretimi (CA, sertifikalar, sırlar, seed)
tests/                   TestKit, UnitTests, IntegrationTests, E2E, Smoke
deploy/                  Dockerfile, docker-compose.yml, .env.example
scripts/                 local-stack, test, smoke, scan, verify, source-fingerprint
docs/                    tasarım belgeleri, ADR'ler, doğrulama raporları
design/preview.html      statik tasarım önizlemesi
```

## Belgeler

| Belge | İçerik |
|---|---|
| `docs/01`–`09` | Gereksinimler, protokol akışları, mimari, veritabanı, API/istemci sözleşmeleri, tehdit modeli, UI tasarımı, uygulama ve test planı |
| `docs/adr/` | Mimari karar kayıtları |
| `docs/security-verification.md` | Güvenlik kabul sözleşmesinin test eşlemesi |
| `docs/revocation-matrix.md` | Hangi olay neyi iptal eder, ne kadar sürede, hangi testle kanıtlı |
| `docs/final-verification.md` | Son doğrulama kapıları, komutlar, sayılar |
| `docs/known-limitations.md` | Bilinçli kapsam dışı ve açık sınırlar |
| `docs/portfolio-summary.md` | Kısa portföy özeti |
| `THIRD-PARTY-NOTICES.md` | Üçüncü taraf bileşenler ve lisansları |

## Lisans

Kaynak kodun sahibi TCoderr'dir; bu depo için ayrı bir açık kaynak lisansı seçilmemiştir. Üçüncü taraf
bileşenler kendi lisanslarına tabidir (`THIRD-PARTY-NOTICES.md`).
