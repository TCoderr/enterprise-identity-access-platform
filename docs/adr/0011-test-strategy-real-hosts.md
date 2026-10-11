# ADR-0011 — Gerçek Kestrel host'ları + Testcontainers + kurulu Chrome

## İhtiyaç
Protokol ve SSO davranışını gerçek HTTP/TLS, gerçek cookie alanları ve gerçek PostgreSQL ile, deterministik zaman kontrolüyle sınamak.

## Seçim
- Her uygulama `Build(args, configure)` fabrika metodu sunar; test harness'ı IAM, Pano, Rapor ve API'yi **aynı süreçte gerçek Kestrel HTTPS** dinleyicileriyle (loopback, dinamik port, public hostname'ler) ayağa kaldırır. TestServer (bellek içi) kullanılmaz.
- Harness bellek içi bir test CA'sı ve leaf sertifikalar üretir; uygulamalar CA'ya normal yapılandırma yoluyla güvenir.
- PostgreSQL: Testcontainers (her test koleksiyonu için atılabilir veritabanı). Migration + grant + seed gerçek Migrator koduyla; uygulamalar **kısıtlı runtime rolüyle** bağlanır.
- Zaman: tüm host'larda ortak `FakeTimeProvider`.
- HTTP "tarayıcı": cookie container'lı, redirect'leri elle izleyen, formları AngleSharp ile okuyan test istemcisi (gerçek antiforgery/OIDC roundtrip).
- Gerçek tarayıcı: Playwright .NET, `channel=chrome` (kurulu Chrome; tarayıcı indirilmez), SPKI pin.

## Daha basit alternatif
`WebApplicationFactory` + TestServer + in-memory DB: cookie alanları, TLS, SameSite, gerçek SQL kısıtları ve rol grant'leri sınanamaz.

## Maliyet
Docker gerekir; testler daha yavaş (container + dört host).

## Sınır
Tek süreçte dört host: ağ katmanı gerçek ama container DNS'i değil — onu Compose smoke kapsar.

## Değişme koşulu
—
