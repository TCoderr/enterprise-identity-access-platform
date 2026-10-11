# ADR-0009 — `*.localhost` hostname'leri, yerel CA, ayrı site'lar

## İhtiyaç
Makinede hosts dosyası/sertifika deposu değiştirmeden, IAM / Pano / Rapor / API için gerçekten ayrı HTTPS origin ve ayrı cookie alanı.

## Seçim
| Servis | URL | Site (eTLD+1) |
|---|---|---|
| IAM | `https://id.halka.localhost:9443` | `halka.localhost` |
| Pano | `https://pano.localhost:9444` | `pano.localhost` |
| Rapor | `https://rapor.localhost:9445` | `rapor.localhost` |
| API | `https://workspace-api.localhost:9446` | `workspace-api.localhost` |

- Chrome `*.localhost` adlarını loopback'e çözer (hosts değişikliği gerekmez). Aynı host'ta farklı port cookie'leri izole etmediği için port ayrımı yeterli sayılmadı; farklı hostname + farklı site seçildi (SameSite gerçekçi sınanır).
- Container içinde her servis public hostname'ini Compose ağ alias'ı olarak taşır ve host portuyla aynı portu dinler → issuer URL'i her yerden aynıdır.
- Doğrulanan: Windows'ta .NET 10 `Dns.GetHostAddresses("x.localhost")` **çözmez**. Bu yüzden host'ta çalışan süreçlerde (testler, `dotnet run`) backchannel `HttpClient`, `Backchannel:LocalhostSubdomainsToLoopback=true` ayarıyla `*.localhost` bağlantılarını loopback'e yönlendirir (RFC 6761 davranışı). Container'da bu ayar kapalıdır; Docker DNS alias'ı kullanılır.
- TLS: `tools/Halka.LocalInit` .NET `CertificateRequest` ile yerel CA ve servis başına leaf sertifika üretir (`.local/tls/`). Servisler CA'ya `LocalCa:CertificatePath` ile **özel kök güveni** (CustomRootTrust) olarak güvenir; sistem deposu değişmez.
- Tarayıcı: kullanıcı isterse `.local/tls/ca.crt` dosyasını kendi kullanıcı deposuna ekler (README'de isteğe bağlı adım) veya uyarıyı geçer. Otomatik testlerde Chrome yalnız test sertifikalarının SPKI özetine güvenir.

## Maliyet
Dört hostname ve sertifika üretimi; tarayıcıda ilk kullanımda güven adımı.

## Sınır
Chromium dışı tarayıcılarda `*.localhost` çözümü farklı olabilir (yalnız Chrome doğrulandı).

## Değişme koşulu
Gerçek alan adı ve genel CA (dağıtım senaryosu).
