# 01 — Ürün Gereksinimleri

Ürün adı: **Halka ID** — yerelde uçtan uca çalışan, production-oriented bir Enterprise Identity & Access Management portföy projesi.
Owner/author: **TCoderr**.

> Sınır: Bu proje formal protokol sertifikasyonundan veya penetrasyon testinden geçmemiştir. "Production-ready / sertifikalı IAM" iddiası yoktur.

## 1. Amaç

Tek bir issuer üzerinden merkezi kimlik sağlayıcı (OpenID Provider + OAuth 2.0 Authorization Server) sunmak; iki ayrı istemci uygulaması arasında gerçek SSO, MFA, uygulama kaydı, consent, oturum/token iptali ve yönetim iş akışlarını kanıtlanabilir biçimde göstermek.

Protokol/kriptografi olgun kütüphaneye (OpenIddict, ASP.NET Core Identity, Otp.NET, ASP.NET Core Data Protection) bırakılır; projenin katkısı iş kuralları, operasyon, güvenlik sözleşmeleri ve ürün deneyimidir.

## 2. Bileşenler

| Bileşen | Origin (yerel) | Rol |
|---|---|---|
| Halka ID (IAM) | `https://id.halka.localhost:9443` | OP/AS: login, hesap, consent, admin UI, protokol endpoint'leri |
| Pano (Demo Client A) | `https://pano.localhost:9444` | Confidential web client (BFF), okuma+yazma scope'ları |
| Rapor (Demo Client B) | `https://rapor.localhost:9445` | Confidential web client (BFF), yalnız okuma scope'u |
| Workspace API | `https://workspace-api.localhost:9446` | Resource server (introspection ile doğrulama) |
| Machine demo | konsol | `client_credentials` ile API çağrısı |
| PostgreSQL | yalnız Compose ağı | Tek kalıcı store |

Dört origin farklı *site*'tır (eTLD+1 farklı); cookie ve SameSite davranışı gerçek cross-site koşullarında sınanır.

## 3. Roller

| Rol | Yetki | Ek koşul |
|---|---|---|
| User | Kendi hesabı, MFA, kendi merkezi oturumları, kendi consent/bağlı uygulamaları | Hassas self-service işlemlerde step-up |
| SecurityAdmin | Kullanıcı disable/enable/unlock, oturum/grant iptali, güvenlik audit okuma | MFA zorunlu; mutasyonda step-up. Client secret/özel anahtar göremez |
| ApplicationAdmin | Client ve scope yönetimi, client disable, secret rotate | MFA zorunlu; secret rotate ve mutasyonda step-up |
| PlatformAdmin | Rol atama, imzalama anahtarı rotasyonu, ops durumu + diğer admin yetkileri | MFA zorunlu; her hassas eylemde yakın zamanlı step-up |

- Public signup yalnız `User` rolü üretir; hiçbir public endpoint admin yaratamaz.
- İlk PlatformAdmin yalnız yerel, private bootstrap (Migrator `seed`) ile oluşur.
- Son aktif PlatformAdmin disable/demote edilemez (yarışa dayanıklı guard).
- Rol/izin her istekte DB'den okunur; cookie içindeki eski rol claim'i yetki vermez.

## 4. Fonksiyonel gereksinimler

### 4.1 Hesap
- F-A1 Signup + demo e-posta doğrulama (private mail sink; gerçek e-posta yok).
- F-A2 Login (generic hata, lockout), logout (current) / logout all ayrımı.
- F-A3 Parola değiştirme, parola sıfırlama (tek kullanımlık, süreli token).
- F-A4 Merkezi oturum listesi ve kendi oturumunu iptal.
- F-A5 MFA: TOTP enrollment/verify/disable, recovery code üretme/yenileme.
- F-A6 Bağlı uygulamalar (consent) listesi ve iptali.
- F-A7 Kendi güvenlik aktivitesi (PII minimum).

### 4.2 Protokol
- F-P1 OIDC discovery + JWKS.
- F-P2 Authorization Code + PKCE S256 (confidential web client).
- F-P3 Refresh token rotation + reuse detection + family revoke.
- F-P4 `client_credentials` (yalnız machine client; kullanıcı claim'i/ID token yok).
- F-P5 UserInfo, revocation (RFC 7009), introspection (RFC 7662), RP-initiated end session.
- F-P6 `prompt=none|login`, `max_age`, `auth_time`, `amr`.
- F-P7 Consent: gerçek client adı + scope açıklamaları, hatırlanan onay, iptal.

### 4.3 Uygulama (client) yönetimi
- F-C1 Client kaydı: tip (web/machine/resource), grant'ler, exact redirect/post-logout URI allowlist, izinli scope'lar, consent politikası.
- F-C2 Client disable/enable (disable anında token/grant iptal eder).
- F-C3 Secret rotation + sınırlı grace penceresi; secret yalnız oluşturma/rotasyon anında bir kez gösterilir.
- F-C4 Scope kaydı (ad, açıklama, resource/audience).

### 4.4 Yönetim/operasyon
- F-O1 Kullanıcı listesi/detayı, disable/enable/unlock, rol atama.
- F-O2 Tüm oturum/grant listesi ve iptali.
- F-O3 Güvenlik audit kaydı (salt-ekleme).
- F-O4 İmzalama anahtarı rotasyonu: overlap, retire, emergency revoke.
- F-O5 Ops durumu: DB, anahtar halkası, outbox/mail kuyruğu, health endpoint'leri.

## 5. Kapsam dışı (bilinçli)

Implicit / ROPC grant, SAML, LDAP/AD/SCIM, sosyal federasyon, gerçek mail/SMS OTP, WebAuthn/passkey, dynamic client registration, keyfi resource server kaydı, multi-issuer/multi-tenant, cihaz güven skoru, policy engine, back-channel logout (bkz. ADR-0006), `acr_values` (yalnız `amr` + `auth_time` yayınlanır), AI/LLM, ERP/SaaS abonelik/finans/lojistik iş alanları.

## 6. Fonksiyonel olmayan gereksinimler

- N1 Anında iptal: iptal edilen oturum/grant/client/kullanıcı için korunan API erişimi bir sonraki istekte reddedilir (varsayılan cache yok).
- N2 Fail closed: IAM/DB erişilemezse resource API erişim vermez (503), geçersiz token (401) ile ayrıştırılır.
- N3 Sır hijyeni: token, parola, TOTP secret, recovery code, client secret log/audit/metric/test artefaktına yazılmaz.
- N4 DB rol ayrımı: migration (owner) ve runtime (kısıtlı) rolleri; audit tablosunda runtime için yalnız INSERT/SELECT.
- N5 Yeniden başlatma: anahtarlar, oturumlar, token durumu ve MFA kayıtları restart sonrası tutarlı.
- N6 Erişilebilirlik: 360/768/1440 px, klavye, focus, label, kontrast, reduced motion.
- N7 Yeniden üretilebilirlik: kilitli restore (`packages.lock.json`), sabit SDK (`global.json`), Compose ile tek komut ayağa kaldırma.

## 7. Demo kullanıcı/rol/client eşlemesi

| Kimlik | Rol | Not |
|---|---|---|
| `admin@halka.test` | PlatformAdmin | Parola `.local/seed/credentials.json`; ilk girişte MFA kaydı zorunlu |
| `secadmin@halka.test` | SecurityAdmin | aynı |
| `appadmin@halka.test` | ApplicationAdmin | aynı |
| `alice@halka.test` | User | MFA isteğe bağlı |

| Client | Tip | Grant | Scope'lar | Consent |
|---|---|---|---|---|
| `pano-web` | confidential web | authorization_code, refresh_token | openid profile email offline_access workspace.read workspace.write | explicit |
| `rapor-web` | confidential web | authorization_code, refresh_token | openid profile offline_access workspace.read | explicit |
| `workspace-api` | resource server | (introspection) | — | — |
| `ops-machine` | machine | client_credentials | workspace.read workspace.jobs | — |
