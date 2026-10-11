# 06 — Tehdit Modeli ve Güvenlik

Yöntem: varlık/aktör/güven sınırı üzerinden senaryo bazlı analiz. Her tehdit için kontrol, kanıtlayan test (bkz. `09-test-and-verification-plan.md`; gerçek sonuçlar `security-verification.md`) ve kalan sınır verilir.

Referanslar: RFC 6749, RFC 7636 (PKCE), RFC 7009, RFC 7662, RFC 8176, RFC 9700 (OAuth 2.0 Security BCP), OpenID Connect Core 1.0, OIDC RP-Initiated Logout 1.0, OpenIddict dokümantasyonu.

## 1. Varlıklar ve aktörler

Varlıklar: kullanıcı kimlik bilgileri, merkezi oturum, token'lar, client secret'lar, imzalama/şifreleme anahtarları, Data Protection anahtarları, TOTP secret'ları, audit kaydı.
Aktörler: anonim internet kullanıcısı, kimlikli kötü niyetli kullanıcı, ele geçirilmiş/kötü niyetli client, ağdaki saldırgan (TLS dışı), çalınmış cookie/token sahibi, yetkisi düşürülmüş eski admin.

## 2. Tehditler

| # | Tehdit | Kontrol | Test (isim öneki) | Kalan sınır |
|---|---|---|---|---|
| T1 | Credential stuffing / brute force | Lockout (5/5 dk), boyutlu rate limit, generic hata, sahte hash ile zamanlama dengeleme | `Login_*`, `RateLimit_*` | Dağıtık saldırıya karşı IP bazlı limit sınırlı; CAPTCHA/risk skoru yok |
| T2 | Kullanıcı enumeration | Login/forgot/signup yanıtları tek tip | `Login_GenericError`, `ForgotPassword_NoEnumeration` | Zamanlama farkı tam sıfırlanamaz |
| T3 | Authorization code interception/replay | PKCE S256 zorunlu, code 2 dk + tek kullanım, client auth, exact redirect | `Code_*` | — |
| T4 | Redirect URI kötüye kullanımı / open redirect | Exact match, wildcard/fragment yok; `returnUrl` yalnız yerel yol; post-logout URI kayıtlı | `Redirect_*`, `ReturnUrl_*`, `EndSession_*` | — |
| T5 | Token confusion (ID token'ı API'de kullanma, yanlış audience) | Introspection `token_usage`, audience kontrolü, issuer sabit | `Api_RejectsIdToken`, `Api_WrongAudience` | — |
| T6 | Refresh token çalınması/reuse | Rotation, tolerans yok, aile + grant iptali, paralel guard | `Refresh_*` | Saldırgan meşru client'tan önce kullanırsa bir kez token alır; meşru kullanımda tespit edilip aile iptal olur |
| T7 | MFA replay | Timestep atomik guard, ±1 adım pencere | `Totp_ParallelSameCode_SingleAccept`, `Totp_Replay` | 30 sn içinde farklı adım kodu ele geçirilirse kullanılabilir (TOTP doğası) |
| T8 | MFA bypass | Pending challenge ayrı cookie; uygulama cookie'si ancak ikinci faktörden sonra; admin MFA zorunlu; trusted-client bayrağı yok | `Mfa_PendingCookie_NotAuthenticated`, `Admin_RequiresMfa` | Recovery code sosyal mühendisliği |
| T9 | Recovery code yarışı | Koşullu UPDATE tek başarı, hash saklama, regenerate eskileri iptal | `Recovery_*` | — |
| T10 | CSRF (login, logout, consent, admin, BFF) | Antiforgery tüm tarayıcı mutasyonlarında; SameSite=Lax; consent POST korumalı | `Csrf_*`, `Consent_ForgedPost` | — |
| T11 | XSS | Razor otomatik encode, CSP (`script-src 'self'`, inline yok), harici script/font yok | `SecurityHeaders_*`, E2E konsol hata kontrolü | CSP `form-action` kısıtı yok (OIDC redirect zinciri nedeniyle) |
| T12 | Session fixation | Her girişte yeni sid + yeni cookie; pending cookie silinir; eski oturum iptal | `Login_RotatesSession` | — |
| T13 | Çalınmış oturum cookie'si | Her istekte DB doğrulaması; logout/revoke sonrası yakalanmış cookie reddedilir | `Session_CapturedCookieAfterLogout_Denied`, E2E global logout | Cookie çalınıp iptal edilene kadar geçerlidir (cihaz bağlama yok) |
| T14 | Eski (stale) rol | Rol her istekte DB'den; step-up oturum satırında | `Admin_RoleRemoved_ImmediateDenial` | — |
| T15 | Private key sızıntısı | Anahtarlar DP ile sarılı; JWKS yalnız public; image/log'da sır yok; non-root; acil rotasyon | `Jwks_NoPrivateMaterial`, `Keys_EmergencyRevoke`, image/log taraması | HSM/KMS yok; `.local/` erişimi olan her şeyi okur |
| T16 | Admin takeover | Admin MFA zorunlu, step-up, last-admin guard, public signup admin üretemez, bootstrap yalnız yerel | `Admin_*`, `LastAdmin_*` | Tek admin hesabının iki faktörü birden ele geçirilirse |
| T17 | IDOR / mass assignment | Sahiplik sunucuda; başkasının oturum/consent id'si 404; binding yalnız izinli alanlar | `Idor_*` | — |
| T18 | Provider (IAM/DB) kesintisi | Resource/BFF fail closed (503), başarılı erişim fallback'i yok | `Outage_*` | Kesintide tüm erişim durur (bilinçli tercih) |
| T19 | Client secret sızıntısı | Hash saklama, tek gösterim, rotasyon + sınırlı grace, disable | `ClientSecret_*` | Grace penceresinde eski secret geçerli |
| T20 | Reset token kötüye kullanımı | 256 bit rastgele, hash'li, 30 dk, tek kullanım (atomik), başarıda tüm oturum/grant iptal; mail sink private | `Reset_*` | Mail kutusu ele geçirilirse hesap devralınır (MFA olsa da reset parolayı değiştirir; MFA korunur) |
| T21 | Log/metric üzerinden sır/PII sızıntısı | Redaksiyon, düşük kardinalite, audit'te IP/e-posta yok | `Logs_NoSecrets`, `Metrics_LowCardinality` | Üçüncü parti kütüphane logları yalnız seviye ile sınırlandı |
| T22 | Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | `SecurityHeaders_*` | — |
| T23 | Karışık içerik / TLS düşürme | Yalnız HTTPS endpoint, HSTS, `Secure` cookie, issuer HTTPS | `Cookies_Secure`, Compose smoke | Yerel CA geliştirme amaçlıdır |
| T24 | Yanlış hedefe test/seed yazımı | Test guard: opt-in + sahiplik işareti + sunucu kimliği | `TestGuard_WrongTarget_ZeroWrites` | — |

## 3. İptal politikası (özet; tam matris `revocation-matrix.md`)

| Eylem | Merkezi oturum | Grant/token |
|---|---|---|
| Logout (current) | Bu oturum biter | Bu oturumun grant'leri iptal |
| Logout all / parola değişimi / parola sıfırlama | Tüm oturumlar biter (parola değişiminde mevcut oturum yenilenir) | Kullanıcının tüm grant'leri iptal |
| MFA disable / re-enroll | Diğer oturumlar biter | Diğer oturumların grant'leri iptal |
| User disable | Tüm oturumlar | Tüm grant'ler; yeni giriş reddedilir |
| Consent revoke | Değişmez | Kullanıcı × client grant'leri iptal; sonraki authorize'da consent yeniden istenir |
| Client disable | Değişmez | Client'ın tüm grant/token'ları (machine dahil) iptal; token/authorize/introspect reddedilir |
| Secret rotate | Değişmez | Token'lar geçerli; eski secret grace sonunda reddedilir |
| Key emergency revoke | Değişmez | Tüm grant/token'lar iptal |

## 4. Bilinçli olarak yapılmayanlar

Cihaz bağlama (DPoP/mTLS), risk tabanlı kimlik doğrulama, CAPTCHA, parola sızıntı listesi kontrolü, HSM/KMS, WAF, dağıtık rate limit, formal sertifikasyon ve pentest. Bunlar `known-limitations.md` içinde tekrar edilir.
