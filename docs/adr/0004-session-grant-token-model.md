# ADR-0004 — Oturum × client başına grant; consent ayrı kayıt

## İhtiyaç
"Bu oturumu kapat", "bu uygulamanın erişimini kaldır", "her yerden çık" eylemlerinin token'lar üzerindeki etkisinin açık, sorgulanabilir ve atomik olması.

## Seçim
- Her başarılı authorization isteği bir OpenIddict **authorization** kaydı üretir; `session_grants` tablosu bunu merkezi oturuma, kullanıcıya ve client'a bağlar.
- Token'lar authorization'a bağlıdır; kütüphane her token doğrulamasında authorization durumunu kontrol eder → grant iptali ailenin tamamını öldürür.
- **Consent** ayrı tablodadır (kullanıcı × client × scope kümesi). OpenIddict'in "permanent authorization = consent" kalıbı kullanılmaz; çünkü oturum bazlı iptal ile kalıcı onay farklı yaşam döngülerine sahiptir.

## Daha basit alternatif
Tek kalıcı authorization (kullanıcı × client): oturum bazlı iptal yapılamaz; "bu cihazdan çık" diğer cihazların token'larını da öldürür veya hiç öldürmez.

## Maliyet
Authorize başına bir authorization satırı (pruning ile temizlenir); bir bağlantı tablosu.

## Sınır
`client_credentials` token'ları grant'e değil client'a bağlıdır; iptali client üzerinden yapılır.

## Değişme koşulu
Çok uzun ömürlü, oturumdan bağımsız offline erişim (ör. arka plan senkronizasyonu) gerekirse oturuma bağlı olmayan kalıcı grant türü eklenir.
