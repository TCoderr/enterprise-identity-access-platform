# ADR-0008 — Protokol anahtarları DB'de, Data Protection ile sarılı

## İhtiyaç
İmzalama anahtarını çalışma zamanında (admin UI, MFA + step-up + audit ile) döndürmek; overlap ve retire kurallarını uygulamak; restart sonrası tutarlılık; private anahtarın kaynak/image/JWKS'e sızmaması.

## Seçim
- `protocol_keys` tablosu: RSA 2048 anahtar çifti (PKCS#8), private kısım Data Protection (`protocol-keys.v1`) ile sarılı. Kullanım: `Signing` (RS256, ID token ve token payload imzası) ve `Encryption` (RSA-OAEP, token payload şifreleme).
- `ProtocolKeyRing` (singleton) DB'den anlık görüntü yükler; `IConfigureOptions<OpenIddictServerOptions>` bu görüntüden kimlik bilgilerini ekler, `IPostConfigureOptions` `Active` anahtarı listenin başına alır. Değişiklikte `IOptionsMonitorCache` temizlenir (OpenIddict options'ı `IOptionsMonitor.CurrentValue` ile çözer — kaynakta doğrulandı).
- İlk açılışta anahtar yoksa Migrator `seed` sırasında üretilir.

## Durumlar
`Active` (imzalar + yayınlanır) → `Retiring` (yalnız doğrulama + JWKS) → `Retired` (kaldırılır). `Revoked` = acil, anında kaldırılır.
Reference token payload'ları da bu anahtarlarla imzalı/şifreli saklandığı için `Retiring` süresi en uzun token ömründen (refresh) kısa olamaz: `retire_not_before = rotated_at + RefreshTokenLifetime + 5 dk`. Erken retire isteği reddedilir.

## İstemci tarafı
- Rotasyondan sonra ilk ID token yeni `kid` taşır. Demo istemciler bilinmeyen `kid` gördüğünde JWKS'i yeniler ve yenileme tamamlanana kadar (en çok 3 sn) bekler; ardından imzayı açık RS256 allowlist'i ile doğrular. JWKS yenileme aralığı 30 sn ile sınırlıdır (bilinmeyen `kid` ile yenileme fırtınası yapılamaz).
- "Önce yayınla, sonra imzala" (pre-publish) ara durumu yoktur: yeni anahtar aynı işlemde hem yayınlanır hem aktif olur. Bu, JWKS'i uzun süre önbellekleyen ve bilinmeyen `kid`'de yenilemeyen üçüncü parti istemciler için bir sınırdır (`docs/known-limitations.md`).

## Daha basit alternatif
Diskte PFX + restart ile rotasyon: çalışma zamanı rotasyonu ve durum takibi yok.

## Maliyet
Options cache yönetimi; anahtar kullanılabilirliği Data Protection key ring'e bağlıdır.

## Sınır
Tek instance doğrulandı (çok instance'ta diğer düğümler periyodik yenileme yapmalı — uygulanmadı). HSM/KMS yok. Şifreleme anahtarı rotasyonu aynı mekanizmayla desteklenir, acil iptalde aynı etki geçerlidir.

## Değişme koşulu
Üretim: KMS/HSM destekli anahtar (ör. Azure Key Vault) ve otomatik zamanlanmış rotasyon.
