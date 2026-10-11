# 02 — Kimlik ve Protokol Akışları

Kütüphane: OpenIddict 7.7.2 (server + validation), ASP.NET Core `OpenIdConnect` handler (istemci). Aşağıdaki davranışlar OpenIddict 7.7.2 kaynak kodu okunarak doğrulanmıştır (`OpenIddictServerHandlers.Protection.cs`, `OpenIddictServerHandlers.cs`, `...Introspection.cs`).

## 1. Endpoint'ler (issuer `https://id.halka.localhost:9443/`)

| Endpoint | Yol | Not |
|---|---|---|
| Discovery | `/.well-known/openid-configuration` | Kütüphane üretir |
| JWKS | `/.well-known/jwks` | Yalnız public anahtar |
| Authorization | `/connect/authorize` | Pass-through; login/MFA/consent iş kuralları |
| Token | `/connect/token` | `authorization_code`, `refresh_token`, `client_credentials` |
| UserInfo | `/connect/userinfo` | Scope'a göre claim |
| Introspection | `/connect/introspect` | Resource server ve BFF oturum doğrulaması |
| Revocation | `/connect/revoke` | RFC 7009 |
| End session | `/connect/endsession` | RP-initiated logout, onay sayfası |

İzin verilmeyenler: implicit, hybrid, password grant, device flow, `response_mode=form_post|fragment`. İstemciler `response_type=code` + `response_mode=query` kullanır.

## 2. Token stratejisi

| Token | Biçim | Ömür (demo) | Doğrulama |
|---|---|---|---|
| Authorization code | opaque referans | 2 dk, tek kullanım | Server DB |
| Access token | opaque **reference token** | 5 dk | Resource server her istekte introspection |
| Refresh token | opaque referans, rotating | 4 saat (her rotasyonda yenilenir; merkezi oturum mutlak ömrüyle sınırlı) | Server DB |
| ID token | imzalı JWT (RS256) | 5 dk | İstemcide OIDC handler (issuer/aud/nonce/imza) |

Gerçek dünya tradeoff'u: reference token + introspection anında iptal sağlar; bedeli her API isteğinde IAM'e bir çağrı ve IAM'in erişilebilirlik bağımlılığıdır (bkz. ADR-0003). Değerler demo içindir; uyumluluk iddiası taşımaz.

## 3. Oturum / grant / token modeli

```
User 1─* CentralSession (user_sessions)            ← tarayıcı cookie'si yalnız sid taşır
CentralSession 1─* Grant (session_grants → OpenIddict Authorization)   ← oturum × client
Grant 1─* Token (OpenIddict Tokens: code, access, refresh)             ← "token ailesi"
User 1─* Consent (consents: user × client × scopes)                    ← hatırlanan onay
Client 1─* ClientCredential (client_secrets: current + grace)
```

- **Central session**: OP tarayıcı oturumu. `auth_time`, `amr`, `password_verified_at`, `mfa_verified_at`, idle/absolute expiry, `revoked_at`.
- **Grant**: Bir merkezi oturumun bir client için verdiği yetki = OpenIddict *authorization* kaydı. Her başarılı authorization isteği yeni grant üretir.
- **Token ailesi**: Bir grant altındaki tüm token'lar. Grant iptal edilince tümü geçersizdir (kütüphane her token doğrulamasında authorization durumunu kontrol eder).
- **Consent**: Token'dan bağımsız karar kaydı; iptali kullanıcının o client'taki tüm grant'lerini de iptal eder.
- **Machine token**: grant'e bağlı değildir; client'a bağlıdır (client disable → iptal).

## 4. Akışlar

### 4.1 Authorization Code + PKCE + MFA + consent

```
Browser        Pano (BFF)            Halka ID                         DB
  │ GET /login    │                      │                             │
  │──────────────▶│ 302 /connect/authorize?response_type=code&code_challenge(S256)&state&nonce
  │──────────────────────────────────────▶│ cookie yok → 302 /account/login?returnUrl=(yerel)
  │ POST parola ─────────────────────────▶│ parola doğru, MFA aktif → mfa_challenge + pending cookie
  │ POST TOTP ───────────────────────────▶│ timestep guard (atomik) → user_sessions INSERT, cookie(sid)
  │ GET /connect/authorize ──────────────▶│ consent yok → consent sayfası (antiforgery)
  │ POST allow ──────────────────────────▶│ consents UPSERT, authorization + session_grants INSERT
  │◀── 302 redirect_uri?code&state ───────│
  │──────────────▶│ POST /connect/token (code, code_verifier, client secret) ──▶ code redeem (tek kullanım)
  │               │◀── access(ref) + refresh(ref) + id_token(JWT)
  │               │ id_token doğrula (iss/aud/nonce/imza), ticket'ı DB'ye şifreli yaz
  │◀─ app cookie ─│  (yalnız oturum anahtarı)
```

### 4.2 SSO (Pano → Rapor)
Rapor `/connect/authorize` çağırır; tarayıcıda geçerli merkezi oturum cookie'si vardır → kimlik bilgisi sorulmaz. Rapor için consent yoksa consent ekranı yine gösterilir; `prompt=login`/`max_age` gerekleri yine uygulanır. Yeni grant (oturum × rapor-web) oluşur.

### 4.3 `prompt` ve `max_age`

| İstek | Durum | Sonuç |
|---|---|---|
| `prompt=none` | oturum yok | `login_required` hatası redirect_uri'ye |
| `prompt=none` | consent gerekli | `consent_required` |
| `prompt=none` | `max_age` aşılmış | `login_required` |
| `prompt=login` | oturum var | Yeniden kimlik doğrulama zorunlu |
| `max_age=N` | `now − auth_time > N` | Yeniden kimlik doğrulama zorunlu |
| `max_age=0` | — | `prompt=login` eşdeğeri |

`prompt=login` atlatılamazlığı: İstek ilk geldiğinde Data Protection ile korunan, HttpOnly bir **reauth cookie** `{istek özeti, issued_at}` yazılır ve login sayfasına yönlendirilir. Dönüşte istek ancak `session.auth_time ≥ issued_at` ise devam eder (yani challenge'dan *sonra* gerçekten giriş yapılmışsa). Eski SSO cookie'si bu koşulu sağlayamaz. `auth_time` her zaman oturum satırından gelir.

### 4.4 Refresh rotation ve reuse

- `RefreshTokenReuseLeeway = null` (tolerans yok).
- Sıralı reuse: kullanılmış refresh token ikinci kez sunulursa kütüphane aileyi (`RevokeByAuthorizationIdAsync`) iptal eder; ek handler grant'i de iptal edip audit yazar. Yanıt: `invalid_grant`.
- Paralel refresh: OpenIddict 7.7.2 refresh grant'te eşzamanlı `TryRedeemAsync` hatasını **yok sayar** (iki istek de yeni token alabilir). Bu yüzden token endpoint'inde SignIn'den önce kendi atomik guard'ımız çalışır: `TryRedeemAsync` (optimistic concurrency) yalnız bir istek için başarılıdır; kaybeden istek reuse sayılır → grant + aile iptal, `invalid_grant`.
- Politika (katı): *Rotasyona uğramış bir refresh token'ın ikinci sunumu, eşzamanlı olsa bile, ele geçirilme sinyalidir; aile iptal edilir.* Kazanan isteğin aldığı yeni token'lar da iptal edilmiş grant'e bağlı olduğundan kullanılamaz. Kullanıcı merkezi oturumu sürüyorsa sessiz SSO ile yeni grant alır.
- Demo istemci eşzamanlı refresh'i oturum başına singleflight kilidiyle seri hâle getirir; meşru kullanımda yarış oluşmaz.

```
Client ──refresh(T1)──▶ AS: T1 valid → guard TryRedeem(T1)=true → T2 üret
Saldırgan ─refresh(T1)─▶ AS: T1 redeemed → grant+aile revoke → invalid_grant
Client ──refresh(T2)──▶ AS: T2 revoked → invalid_grant   (API: access token active=false)
```

### 4.5 Introspection ile API doğrulaması
Resource server her istekte `POST /connect/introspect` çağırır (client kimlik doğrulamalı). IAM token kaydı + grant durumu + oturum durumu + kullanıcı durumu + client durumunu kontrol eder. `active:false` → 401. IAM/DB erişilemez veya zaman aşımı → 503 (fail closed). ID token API'de kabul edilmez (`token_usage` kontrolü).

### 4.6 Logout

| Eylem | Etki |
|---|---|
| RP yerel logout (Pano "Sign out of Pano") | Pano app oturumu silinir, Pano'nun token'ları revocation endpoint'iyle iptal edilir. OP oturumu ve Rapor etkilenmez; tekrar login sessiz SSO olur |
| RP-initiated end session (`/connect/endsession`) | `id_token_hint` + kayıtlı `post_logout_redirect_uri` doğrulanır; onay sayfası (antiforgery) → merkezi oturum + tüm grant'leri iptal; Pano ve Rapor bir sonraki istekte oturumu kaybeder |
| "Sign out everywhere" (hesap sayfası) | Kullanıcının tüm merkezi oturumları + grant'leri iptal |

Back-channel logout desteklenmez (OpenIddict server'da yok); yerine BFF her istekte access token introspection'ı ile server-state kontrolü yapar (ADR-0006).

### 4.7 `client_credentials`
Yalnız `ept:token` + `gt:client_credentials` izni olan machine client. Token `sub = client_id` taşır; kullanıcı claim'i, ID token, refresh token yoktur. Scope'lar client izinleriyle sınırlıdır.

### 4.8 İmzalama anahtarı rotasyonu

Durum makinesi: `Active → Retiring → Retired`, acil durumda `* → Revoked`.

- Rotate: yeni anahtar `Active` olur (yeni token'lar yeni `kid` ile imzalanır); eski anahtar `Retiring` olur, JWKS'te ve doğrulamada kalır.
- Retire: yalnız `retire_not_before = rotated_at + en uzun token ömrü (refresh) + skew` geçtikten sonra mümkündür; aksi hâlde reddedilir (geçerli token'lar sessizce kırılmaz).
- Emergency revoke: anahtar hemen JWKS/doğrulamadan çıkar; o anahtarla imzalanmış tüm token'lar geçersiz olur; ayrıca tüm grant/token kayıtları iptal edilir (global yeniden giriş).

### 4.9 OP erişilemezliği
- Resource API: introspection hatası → 503 + `Retry-After`, erişim yok.
- BFF: oturum doğrulaması yapılamazsa korunan sayfa 503 gösterir; oturum silinmez, erişim de verilmez.
- İstemci discovery/JWKS cache'i kütüphane varsayılanlarıyla yenilenir; imza anahtarı bulunamazsa handler metadata'yı yeniler.

## 5. Claim'ler

| Claim | ID token | Access token (introspection) | UserInfo | Koşul |
|---|---|---|---|---|
| `sub` | ✔ | ✔ | ✔ | her zaman |
| `name`, `preferred_username` | ✔ | — | ✔ | `profile` |
| `email`, `email_verified` | ✔ | — | ✔ | `email` |
| `auth_time`, `amr` | ✔ | ✔ | — | kullanıcı akışı |
| `scope`, `aud`, `client_id` | — | ✔ | — | kütüphane |

`amr` değerleri (RFC 8176): `pwd`; TOTP ile `pwd otp mfa`; recovery code ile `pwd mfa`. `acr` yayınlanmaz. Standart dışı claim icat edilmez.

## 6. Hata sözleşmesi
- Protokol endpoint'leri: OAuth/OIDC standart hata yanıtları (`error`, `error_description`); ProblemDetails'e çevrilmez.
- Ürün JSON API'leri ve resource API: RFC 9457 ProblemDetails; resource API ayrıca `WWW-Authenticate: Bearer error=...` üretir.
