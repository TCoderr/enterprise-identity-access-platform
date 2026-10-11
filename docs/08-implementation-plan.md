# 08 — Uygulama Planı

Aşamalar sırayla uygulanır; bir aşamanın kabul kapısı geçmeden sonrakine geçilmez. Durum takibi `implementation-progress.md`, bir sonraki adım `next-action.md` içindedir.

| Aşama | Kapsam | Ana çıktılar | Kabul kapısı |
|---|---|---|---|
| 1 | Solution, Identity, merkezi oturum | Proje iskeleti, `IamDbContext` + ilk migration, signup/confirm/login/logout, oturum doğrulama, outbox + mail sink, CSRF, health/OpenAPI, Migrator, test altyapısı | Generic hata/lockout; session fixation guard; logout sonrası yakalanmış cookie reddi; disabled kullanıcı reddi; private sink; kısıtlı DB rolleri |
| 2 | Docker/HTTPS/anahtar/CI temeli | `LocalInit`, Dockerfile'lar, Compose, script'ler, kilitli restore, CI workflow | Boş init/up + restart; container DNS ile discovery; secure cookie; non-root; DB down/up; image/log'da sır yok; anahtar depolama restart tutarlı |
| 3 | Client registry, scope, OIDC code flow | OpenIddict server, anahtar halkası, authorize/token, Pano + Workspace API | Code+PKCE başarı; yanlış verifier/client/redirect/reuse/expiry; tampered ID/access; yanlış issuer/audience; API'de ID token reddi; least scope |
| 4 | Consent ve iki uygulama SSO | Consent ekranı/kaydı, Rapor, prompt/max_age, UserInfo | A login → B kimlik bilgisiz SSO; prompt none/login/max_age; forged consent; yanlış app scope; metadata'da secret yok; iki origin gerçek tarayıcı |
| 5 | MFA ve admin step-up | TOTP/recovery, enrollment, replay guard, challenge, admin MFA zorunluluğu | Geçerli/geçersiz/skew/expired challenge; paralel aynı TOTP tek kabul; recovery paralel tek kabul; eski kod reddi; disable/reset reauth; admin bypass yok |
| 6 | Refresh, revoke, global logout | Rotation/reuse guard, introspection handler, BFF singleflight + doğrulama, revocation, end-session | Concurrent refresh/reuse aile etkisi; grant/user/app revoke anında API reddi; global logout sonrası çalınmış A/B cookie reddi; logout redirect tamper reddi; outage fail closed |
| 7 | client_credentials, credential/key lifecycle | Machine client, secret grace, anahtar overlap/retire/emergency | Yanlış credential / kullanıcı token'ı yok; yanlış scope; rotate old/new pencere; private key JWKS'te yok; yeni kid + eski token doğrulama; disabled machine reddi; anahtar kalıcılığı |
| 8 | Hesap/admin/UI tam iş akışları | Tüm admin ve self-service sayfaları, demo UI | Build/component/E2E; rol düşürme + last-admin yarışı; owner IDOR; mobil klavye; secret tek gösterim; logout sonrası cache temiz |
| 9 | Recovery/ops/hardening | Parola reset akışı, worker güvenilirliği, retention, rate limit, log/metric, tarama | Reset token tek kullanım/expiry/concurrent + revoke politikası; worker recovery; log'da token/PII yok; unavailable hata uyumluluğu; dış sızıntı yok |
| 10 | Final kapılar/dokümanlar | Final doğrulama, raporlar, fingerprint | Kritik kapılar pass / skip yok; engel varsa dürüst kısmi |

## Uygulama sırası ilkeleri

- Bağımlı işler eşzamanlı geliştirilmez (ör. BFF oturum doğrulaması introspection'dan sonra).
- UI temeli (layout + CSS) Aşama 1'de kurulur; ekranlar ilgili aşamada gerçek davranışla gelir.
- Her aşama sonunda: kararlar, değişen dosyalar, komut + exit code, test sayıları (pass/fail/skip), kaynak fingerprint'i ve sonraki adım `implementation-progress.md`'ye yazılır.
- Kaynak değiştiyse eski test sonuçları geçerli sayılmaz; ilgili kapı yeniden koşulur. Final kapıları aynı kaynak durumunda koşulur.

## Kesinti/devam

Devam eden oturum önce `docs/implementation-progress.md` ve `docs/next-action.md` dosyalarını, sonra kaynakları okur; projeyi baştan üretmez. `next-action.md` her zaman çalıştırılabilir tam komutu içerir.
