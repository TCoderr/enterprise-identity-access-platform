# ADR-0003 — Reference access token + introspection

## İhtiyaç
Ürün hedefi: oturum/grant/kullanıcı/client iptalinde korunan API erişiminin **anında** kesilmesi.

## Seçenekler

| Seçenek | İptal gecikmesi | İstek maliyeti | IAM kesintisinde |
|---|---|---|---|
| Self-contained JWT, yalnız imza doğrulama | Token ömrü kadar (dk) | Yok | API çalışmaya devam eder |
| JWT + her istekte introspection | Anında | 1 HTTP + DB | Fail closed |
| **Reference token + introspection** (seçim) | Anında | 1 HTTP + DB | Fail closed |
| Reference/JWT + kısa cache | Cache süresi kadar | Azalır | Cache süresince çalışır |

Self-contained JWT'yi yalnız imzayla doğrulayıp "anında iptal" iddia etmek yanlıştır; bu yüzden elendi.

## Seçim
Access ve refresh token'lar opaque reference token'dır (`UseReferenceAccessTokens`, `UseReferenceRefreshTokens`). Resource server `OpenIddict.Validation` + introspection kullanır; varsayılan **cache yok**. ID token imzalı JWT olarak kalır (istemcide doğrulanır).

Introspection sırasında kütüphane token ve authorization kaydını DB'den doğrular; ek handler oturum süresi/kullanıcı/client durumunu da kontrol eder.

## Maliyet
Her API isteğinde IAM'e bir çağrı (yerelde ~birkaç ms); IAM erişilebilirliği API erişilebilirliğinin üst sınırıdır.

## Sınır
IAM/DB kesintisinde API 503 döner (bilinçli fail closed). Opaque token içeriği istemci tarafından okunamaz (istenen özellik).

## Değişme koşulu
Latency/erişilebilirlik hedefi istek başına çağrıyı kaldıramazsa: sınırlı (ör. ≤ 30 sn) introspection cache'i açılır ve iptal gecikmesi bu değerle **belgelenir**; "anında" ifadesi kaldırılır.
