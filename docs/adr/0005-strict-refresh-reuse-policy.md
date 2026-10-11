# ADR-0005 — Katı refresh reuse politikası + paralel guard

## Bulgu (OpenIddict 7.7.2 kaynak kodu)
- `ValidateTokenEntry`: `Redeemed` durumundaki refresh token yeniden sunulursa ve leeway dışındaysa `RevokeByAuthorizationIdAsync` ile aile iptal edilir; authorization kaydı iptal edilmez. Varsayılan `RefreshTokenReuseLeeway` = 30 sn.
- `RedeemTokenEntry`: refresh grant'te `TryRedeemAsync` sonucu **yok sayılır** ("ignore errors ... caused by concurrent requests"). Sonuç: doğrulamayı aynı anda geçen iki istek ikisi de yeni token alabilir (aile çatallanır).

## İhtiyaç
"Paralel iki refresh'ten yalnız biri rotate eder" ve reuse'un aileye etkisinin deterministik olması.

## Seçim
1. `SetRefreshTokenReuseLeeway(null)` — tolerans yok.
2. Token endpoint'inde (pass-through) SignIn'den önce **kendi atomik guard'ımız**: `IOpenIddictTokenManager.TryRedeemAsync(token)` (optimistic concurrency). Yalnız bir istek kazanır.
3. Kaybeden istek ve sıralı reuse aynı sonuca gider: grant (authorization) + tüm token'lar iptal, audit `refresh_token.reuse_detected`, yanıt `invalid_grant`.
4. Demo BFF, refresh'i oturum başına singleflight kilidiyle seri yapar.

## Değişmezler (testlerle doğrulanır)
- Aynı refresh token ile N eşzamanlı istek → tam olarak 1 adet `200`.
- Ardından: grant `revoked`; kazananın yeni refresh token'ı `invalid_grant`; yeni access token introspection'da `active:false`.

## Uygulama notları
- Toplu iptal authorization satırının `concurrency_token` değerini değiştirir, token satırlarınınkini değiştirmez. Aksi halde yarışı kazanan istek kendi yeni token'larını yazarken çakışır ve hiç `200` çıkmayabilirdi (testte görüldü ve düzeltildi). Kazananın yazdığı token'lar, authorization iptal olduğu için kullanılamaz (inert).
- Token üretimi sırasında kütüphane eşzamanlılık çakışması bildirirse (`ConcurrencyException`) yanıt standart OAuth hatasıdır (`invalid_grant` / `invalid_client`), 500 değildir.
- Kanıt yarışı uyku (sleep) ile değil değişmezlerle kurulur: 10 tur × eşzamanlı istek, her turda tam 1 başarı.

## Daha gevşek alternatif
Leeway ile yarışı tolere etmek: meşru istemci hatalarını affeder ama saldırgan/meşru ayrımı yapılamaz ve aile çatallanabilir. RFC 9700 §4.14.2 reuse'da iptali önerir.

## Maliyet
Singleflight kullanmayan hatalı bir istemci yarışta oturumunu kaybeder (merkezi oturum sürüyorsa sessiz SSO ile toparlar).

## Değişme koşulu
Kontrol edilemeyen üçüncü parti (ör. mobil/native) istemciler eklenirse kısa bir leeway + çatallanmayı engelleyen idempotent rotasyon değerlendirilir.
