# ADR-0001 — OpenIddict 7.7.2 ile bağımsız authorization server

## İhtiyaç
OAuth 2.0 / OIDC protokol katmanını (token üretim/doğrulama, discovery/JWKS, PKCE, refresh, introspection, revocation, end-session) el yazısı kod olmadan sağlamak; iş kurallarını (login, MFA, consent, iptal) kendi kodumuzda tutmak.

## Doğrulanan gerçek durum (2026-10-11)
- OpenIddict **7.7.2** (yayın: 2026-10-10), lisans **Apache-2.0** (GitHub API `license.spdx_id`), ücretsiz.
- NuGet: `OpenIddict.AspNetCore`, `OpenIddict.EntityFrameworkCore`, `OpenIddict.Validation.AspNetCore`, `OpenIddict.Validation.SystemNetHttp` 7.7.2; .NET 10 hedefiyle restore/build edilir (kilit dosyası ile sabit).
- Kaynak okunarak doğrulananlar: reference token desteği, introspection'da audience/presenter ve `token_usage` kontrolü, refresh reuse'da aile iptali, `RefreshTokenReuseLeeway`, options'ın `IOptionsMonitor` ile çözülmesi.
- Desteklenmeyen: OIDC Back-Channel Logout (bkz. ADR-0006).
- Formal OpenID sertifikasyonu bu yapılandırma için koşulmadı.

## Seçim
OpenIddict server (pass-through authorize/token/userinfo/endsession) + ASP.NET Core Identity (kullanıcı/parola/lockout) + EF Core/PostgreSQL store.

## Alternatifler
| Alternatif | Neden seçilmedi |
|---|---|
| Keycloak + proxy | Proje hedefi iş kurallarını ve operasyonu .NET'te geliştirmek; hazır ürün ekranı hedefi karşılamaz |
| Duende IdentityServer | Ticari lisans (belirli gelir/kullanım üstünde ücretli); portföy için maliyet/lisans uyumu zayıf |
| El yazısı OAuth | Yasak ve riskli |

## Maliyet
Pass-through controller'lar ve birkaç özel handler yazılır; OpenIddict şemasına bağımlılık.

## Sınır
Back-channel logout yok; refresh grant'te eşzamanlı redeem hatası kütüphanede yok sayılır (ADR-0005 ile kapatıldı).

## Değişme koşulu
Lisans/bakım durumu değişirse veya back-channel logout/federasyon zorunlu olursa yeniden değerlendirilir.
