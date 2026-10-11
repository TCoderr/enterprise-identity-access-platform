# ADR-0007 — Otp.NET + atomik timestep guard

## İhtiyaç
TOTP (RFC 6238) doğrulaması; sınırlı saat kayması; aynı timestep kodunun eşzamanlı ikinci kullanımının reddi; secret'ın at-rest korunması; deterministik test (sahte saat).

## Bulgu
ASP.NET Core Identity `AuthenticatorTokenProvider`: ±2 adım pencere kullanır, eşleşen adımı döndürmez (replay guard kurulamaz), secret'ı `user_tokens` içinde düz saklar ve recovery code'ları düz metin listesi olarak tutar.

## Seçim
- Kod hesaplama/doğrulama: **Otp.NET 1.4.1** (MIT) `Totp.VerifyTotp(timestamp, code, out matchedStep, window)`; pencere ±1 adım; zaman `TimeProvider`'dan.
- Replay guard: `UPDATE user_mfa SET last_accepted_step = @matched WHERE user_id = @u AND last_accepted_step < @matched` — etkilenen satır 1 ise kabul. Aynı kodla paralel iki istekten yalnız biri geçer; daha eski adımlar da reddedilir.
- Secret: 160 bit CSPRNG; Data Protection (`mfa.totp.v1` amacı) ile sarılıp `user_mfa.protected_secret` içinde. Yalnız enrollment ekranında gösterilir.
- Recovery code: 10 adet, 80 bit CSPRNG, base32 gruplu gösterim; SHA-256 hash; tek kullanım koşullu UPDATE; regenerate eski batch'i siler.
- QR: sunucuda SVG (QRCoder, MIT); harici servis yok.

## Maliyet
Küçük özel doğrulama servisi (kripto yazılmaz; yalnız kütüphane çağrısı + guard).

## Sınır
Data Protection anahtarı kaybolursa secret'lar çözülemez (kullanıcılar MFA'yı yeniden kurar; admin destekli akış audit'lenir). SMS/e-posta OTP ve WebAuthn yok.

## Değişme koşulu
Passkey/WebAuthn gereksinimi.
