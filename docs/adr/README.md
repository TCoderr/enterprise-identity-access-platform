# Mimari Karar Kayıtları (ADR)

Her kayıt: ihtiyaç, seçim, daha basit alternatif, maliyet, sınır, değişme koşulu.

| # | Karar | Durum |
|---|---|---|
| [0001](0001-openiddict-authorization-server.md) | OpenIddict 7.7.2 ile bağımsız authorization server | Kabul |
| [0002](0002-razor-pages-server-rendered-ui.md) | Razor Pages (server-rendered) UI; React yok | Kabul |
| [0003](0003-reference-tokens-and-introspection.md) | Reference access token + introspection ile anında iptal | Kabul |
| [0004](0004-session-grant-token-model.md) | Oturum × client başına grant; consent ayrı kayıt | Kabul |
| [0005](0005-strict-refresh-reuse-policy.md) | Katı refresh reuse politikası + paralel guard | Kabul |
| [0006](0006-server-state-check-instead-of-backchannel-logout.md) | Back-channel logout yerine BFF server-state kontrolü | Kabul |
| [0007](0007-totp-otpnet-and-replay-guard.md) | Otp.NET + atomik timestep guard; secret DP ile sarılı | Kabul |
| [0008](0008-protocol-keys-in-database.md) | Protokol anahtarları DB'de DP ile sarılı; rotasyon durum makinesi | Kabul |
| [0009](0009-local-hostnames-and-tls.md) | `*.localhost` hostname'leri, yerel CA, ayrı site'lar | Kabul |
| [0010](0010-mail-outbox-and-file-sink.md) | DB outbox + leased worker + private dosya sink | Kabul |
| [0011](0011-test-strategy-real-hosts.md) | Gerçek Kestrel host'ları + Testcontainers + kurulu Chrome | Kabul |
