# ADR-0002 — Razor Pages (server-rendered) UI

## İhtiyaç
Login, MFA, consent, hesap ve admin ekranları; iki demo istemci arayüzü. Güvenlik ekranlarında küçük saldırı yüzeyi ve basit CSP.

## Seçim
IAM ve demo istemciler Razor Pages ile server-rendered; küçük, bağımlılıksız vanilla JS (progressive enhancement: kod alanı temizleme, kopyalama, onay). Elle yazılmış tek CSS dosyası.

## Daha basit alternatif / neden React değil
React SPA: token/oturum durumunu tarayıcıda yönetme, ayrı build hattı, daha gevşek CSP ve daha büyük XSS yüzeyi getirir. Bu ürünün ekranları form + tablo ağırlıklıdır; SPA etkileşimi gerekmez. Auth ekranlarının OIDC redirect akışında server-rendered olması zaten zorunludur.

## Maliyet
Zengin istemci etkileşimi yok; tam sayfa yenileme.

## UI kapılarının karşılığı
| Kapı | Bu mimarideki karşılığı |
|---|---|
| Typecheck | `tsc --noEmit --checkJs` (JSDoc tipli JS) |
| Lint | ESLint |
| Prod build | `dotnet publish -c Release` (Razor derleme + statik varlıklar) |
| Component | Razor sayfa render testleri (gerçek HTTP + AngleSharp) ve `node --test` ile JS modül testleri |

## Değişme koşulu
Gerçek zamanlı/yoğun etkileşimli yönetim ekranı ihtiyacı doğarsa admin alanı için ayrı bir SPA değerlendirilir; auth ekranları server-rendered kalır.
