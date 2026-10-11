# ADR-0006 — Back-channel logout yerine BFF server-state kontrolü

## İhtiyaç
Merkezi logout / "logout all" / admin iptali sonrası Pano ve Rapor'un eski app cookie'siyle korunan kaynağa erişememesi.

## Bulgu
OpenIddict server 7.7.2, OIDC Back-Channel Logout (logout token üretimi/teslimi) sağlamaz. Bunu elle uygulamak, imzalı logout token üretimi ve teslim güvenilirliği gibi protokol kodunu kendimiz yazmak demektir (kapsam ve ilke dışı).

## Seçim
BFF her kimlikli istekte access token'ını IAM introspection endpoint'ine sorar (client kimlik doğrulamalı, istemci token'ın *presenter*'ıdır). Merkezi oturum iptal edildiğinde grant'leri de iptal edildiği için yanıt `active:false` olur → app oturumu sunucu tarafında silinir.

## Maliyet
BFF isteği başına bir IAM çağrısı. `SessionValidationCacheSeconds` ayarıyla sınırlı cache açılabilir; varsayılan `0` (anında).

## Sınır
- Kullanıcı istemciye istek atmadıkça app oturumu "pasif olarak" durur; ilk istekte düşer. Tarayıcıda açık kalan sayfa içeriği `no-store` olsa da ekranda kalabilir.
- IAM erişilemezse BFF korunan sayfalarda 503 verir (fail closed).

## Değişme koşulu
Kütüphane back-channel logout desteği eklerse veya üçüncü parti RP'ler desteklenecekse standart mekanizmaya geçilir.
