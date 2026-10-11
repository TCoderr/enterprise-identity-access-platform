# 05 — API ve İstemci Sözleşmeleri

## 1. Scope / resource / audience

| Scope | Resource (aud) | Anlam | İzinli client'lar |
|---|---|---|---|
| `openid` | — | OIDC kimlik | pano-web, rapor-web |
| `profile` | — | `name`, `preferred_username` | pano-web, rapor-web |
| `email` | — | `email`, `email_verified` | pano-web |
| `offline_access` | — | Refresh token | pano-web, rapor-web |
| `workspace.read` | `workspace-api` | Notları okuma | pano-web, rapor-web, ops-machine |
| `workspace.write` | `workspace-api` | Not ekleme | pano-web |
| `workspace.jobs` | `workspace-api` | Makine iş durumu | ops-machine |

Bir client izinli olmadığı scope'u isterse authorization/token isteği `invalid_scope`/`invalid_request` ile reddedilir (kütüphane scope permission kontrolü).

## 2. Client kayıt sözleşmesi

| Alan | Kural |
|---|---|
| `client_id` | Sunucu doğrular: `[a-z0-9-]{3,64}`, benzersiz, değiştirilemez |
| Tür | `Web` (confidential, code+refresh), `Machine` (confidential, client_credentials), `Resource` (introspection) |
| Redirect URI | Mutlak `https`, fragment yok, wildcard yok, tam eşleşme; loopback geliştirme URI'ları da açıkça kaydedilir |
| Post-logout URI | Aynı kurallar |
| Scope'lar | Yalnız kayıtlı scope'lar; `Machine` için `openid/profile/email/offline_access` verilemez |
| Consent | `explicit` (hatırlanır), `systematic` (her seferinde), `implicit` (ilk-parti, ekran yok) |
| Secret | CSPRNG 32 bayt, base64url; yalnız oluşturma/rotasyon yanıtında bir kez; liste/detay asla döndürmez |

Client id, session id, grant id gibi tanımlayıcılar sunucu tarafından üretilir/doğrulanır; form'dan gelen sahiplik alanlarına güvenilmez (mass assignment/IDOR engeli).

## 3. IAM ürün yüzeyi (server-rendered)

Tarayıcı mutasyonlarının tümü `POST` + antiforgery token'dır. Sayfa yolları:

| Alan | Yol | Yetki |
|---|---|---|
| Hesap | `/account/login`, `/account/mfa`, `/account/recovery`, `/account/register`, `/account/confirm-email`, `/account/forgot-password`, `/account/reset-password`, `/account/logout`, `/account/step-up` | anonim / oturum |
| Self-service | `/manage`, `/manage/password`, `/manage/mfa`, `/manage/mfa/enroll`, `/manage/mfa/recovery-codes`, `/manage/sessions`, `/manage/apps`, `/manage/activity` | oturum (+ step-up) |
| Admin | `/admin`, `/admin/users`, `/admin/users/{id}`, `/admin/clients`, `/admin/clients/new`, `/admin/clients/{id}`, `/admin/scopes`, `/admin/sessions`, `/admin/grants`, `/admin/audit`, `/admin/keys`, `/admin/ops` | rol + MFA (+ step-up) |

### JSON ürün API'si (ProblemDetails)

| Yol | Metot | Yetki | Not |
|---|---|---|---|
| `/health/live`, `/health/ready` | GET | anonim | Ayrıntı sızdırmaz |
| `/api/account/session` | GET | oturum | Mevcut oturum özeti (sid kısaltılmış, amr, auth_time, step-up durumu) |
| `/api/account/sessions/{id}` | DELETE | oturum + antiforgery header | Yalnız kendi oturumu; başkasınınki 404 |
| `/openapi/v1.json` | GET | Development/Testing | Ürün API şeması |

## 4. Workspace API (resource server)

`Authorization: Bearer <opaque access token>`; her istekte introspection.

| Yol | Metot | Politika | Not |
|---|---|---|---|
| `/notes` | GET | `workspace.read` | Kullanıcı veya makine token'ı |
| `/notes` | POST | `workspace.write` + kullanıcı token'ı | Makine token'ı reddedilir |
| `/notes/sensitive` | GET | `workspace.read` + `amr∋mfa` + `auth_time` ≤ 15 dk | "MFA gerekli" tazelik politikası |
| `/jobs/status` | GET | `workspace.jobs` + makine token'ı | |
| `/health/live` | GET | anonim | |

| Durum | Yanıt |
|---|---|
| Token yok/geçersiz/iptal/expired | `401` + `WWW-Authenticate: Bearer error="invalid_token"` |
| Scope yetersiz | `403` + `WWW-Authenticate: Bearer error="insufficient_scope"` + ProblemDetails |
| MFA/tazelik yetersiz | `403` + ProblemDetails `type=.../step-up-required` |
| IAM erişilemez / zaman aşımı | `503` + `Retry-After` + ProblemDetails `type=.../authorization-server-unavailable` |

Veri demo amaçlı process belleğindedir (API'nin kalıcı store'u kapsam dışı).

## 5. Demo istemci (BFF) sözleşmesi

- OIDC: `response_type=code`, PKCE S256, `response_mode=query`, `state` + `nonce` handler tarafından doğrulanır.
- Token'lar tarayıcıya gitmez; auth ticket DP ile şifrelenip `app_sessions` tablosunda tutulur, cookie yalnız anahtar taşır.
- Cookie: `__Host-<app>-session` — `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`. Correlation/nonce cookie'leri handler varsayılanı (`SameSite=None; Secure; HttpOnly`, kısa ömür).
- Her kimlikli istekte: (1) access token'ın bitmesine < 60 sn varsa oturum başına singleflight ile refresh; (2) introspection ile server-state doğrulaması; `active:false` → app oturumu silinir, IAM erişilemez → 503.
- Mutasyonlar `POST` + antiforgery; korunan sayfalar `Cache-Control: no-store`; logout yanıtı `Clear-Site-Data: "cache"` gönderir.

| Yol | Metot | Not |
|---|---|---|
| `/` | GET | Durum: anonim veya oturum rozeti |
| `/login` | GET | Tarayıcı navigasyonu ile challenge (fetch değil); `returnUrl` yalnız yerel yol |
| `/login/fresh` | POST | `prompt=login` ile yeniden kimlik doğrulama; dönüşte `auth_time` tazeliği istemcide doğrulanır |
| `/signin-oidc`, `/signout-callback-oidc` | — | Handler callback'leri |
| `/session` | GET | Kullanıcı, scope'lar, `amr`, `auth_time`, token bitiş zamanı (ham token yok) |
| `/workspace` | GET/POST | API çağrıları: oku, yaz, hassas oku |
| `/session/refresh` | POST | Zorla refresh |
| `/logout/local` | POST | Yalnız bu uygulama + kendi token'larını revoke |
| `/logout/global` | POST | RP-initiated end session |

## 6. Rate limit boyutları

| Politika | Bölüm anahtarı | Varsayılan |
|---|---|---|
| `login` | IP + normalize kullanıcı adı özeti | 10 / dk |
| `login-ip` | IP | 60 / dk |
| `mfa` | challenge id (yoksa IP) | 10 / dk |
| `recovery` | IP | 5 / dk (forgot/reset/confirm) |
| `signup` | IP | 10 / saat |
| `token` | `client_id` + IP | 120 / dk |

Limit aşımı: UI için `429` sayfası, token endpoint için `429` + `Retry-After`. Tüm kullanıcı/client'ler tek kovaya düşmez.
