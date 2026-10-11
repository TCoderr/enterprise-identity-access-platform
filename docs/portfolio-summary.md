# Portföy Özeti — Halka ID

**Yazar / sahip:** TCoderr · **Teknoloji:** C# / .NET 10, ASP.NET Core (Razor Pages), ASP.NET Core Identity,
EF Core + PostgreSQL 17, OpenIddict 7.7.2, Docker Compose · **Tür:** yerelde uçtan uca çalışan referans uygulama

## Ne işe yarar

Bir kurumun birden çok iç uygulaması olduğunda her uygulamanın kendi kullanıcı tablosu, kendi parola kuralı ve
kendi "çıkış" düğmesi olur; bir çalışan ayrıldığında ya da bir hesap ele geçirildiğinde erişimi her yerde ayrı ayrı
kapatmak gerekir. Halka ID bu sorunu tek bir kimlik sağlayıcıda toplar:

- **Tek oturum açma (SSO):** kullanıcı bir kez (gerekirse ikinci faktörle) giriş yapar; diğer uygulamalar parola
  sormadan açılır, her uygulama yalnız kendisine tanınan izinleri alır.
- **Merkezi iptal:** oturum, uygulama izni, kullanıcı ya da uygulama tek yerden kapatılır ve bu, uygulamalarda ve
  API'de **bir sonraki istekte** geçerli olur.
- **Güçlü doğrulama:** TOTP + kurtarma kodları; yöneticiler için zorunlu, hassas işlemlerde taze doğrulama.
- **Uygulama yönetimi:** istemci kaydı, izin (scope) sınırları, secret ve imza anahtarı rotasyonu, denetim kaydı.

İki demo uygulama (Pano, Rapor), korunan bir API ve bir makine istemcisi bu davranışları gerçek HTTPS origin'leri
üzerinde gösterir.

## Öne çıkan mühendislik tercihleri

| Tercih | Neden | Bedeli |
|---|---|---|
| Protokol için olgun kütüphane (OpenIddict); elle JWT / kripto yok | OAuth / OIDC ayrıntılarında hata maliyeti yüksek | Kütüphane davranışlarını kaynak koddan doğrulamak gerekti (ör. eşzamanlı refresh) |
| Reference token + introspection, önbelleksiz | "İptal anında geçerli" iddiasını dürüstçe verebilmek | Her API isteğinde sağlayıcıya çağrı; sağlayıcı yoksa API 503 |
| Oturum × istemci başına "grant"; cookie yalnız kimlik taşır | Her iptal eyleminin etkisi tek transaction'da ve tabloyla açıklanabilir | İstek başına veritabanı okuması |
| Eşzamanlılık kuralları veritabanında (koşullu UPDATE, benzersiz indeks, advisory lock) | TOTP adımı, kurtarma kodu, tek kullanımlık bağlantı, refresh, son yönetici, aktif anahtar yarışları deterministik | Daha fazla tasarım ve test |
| BFF: token'lar tarayıcıya hiç gitmez | XSS ile token çalınamaz | Uygulama sunucusunda oturum deposu |
| Fail-closed kesinti davranışı | Doğrulanamayan oturum / token "geçerli" sayılmaz, "geçersiz" de denmez | Sağlayıcı kesintisinde uygulamalar 503 verir |
| Sunucu taraflı Razor Pages, harici kaynak yok | Kimlik ekranlarında küçük saldırı yüzeyi, sıkı CSP | Zengin istemci etkileşimi yok |

Ayrıntı: `docs/adr/` (11 karar kaydı), `docs/06-threat-model-and-security.md`.

## Doğrulanmış güvenceler

Aşağıdakiler otomatik testlerle kanıtlıdır; hepsi aynı kaynak durumunda yerelde koşulmuştur (sayılar, kaynak
fingerprint'i ve komutlar: `docs/final-verification.md`; test eşlemesi: `docs/security-verification.md`,
`docs/revocation-matrix.md`). Sonradan yapılan iki kozmetik düzeltmenin ardından yalnız etkilenen kontroller
yeniden koşulmuştur (aynı belgede ayrı kayıt). Uzak CI koşulmamıştır.

- Authorization code + PKCE: yanlış verifier / client / redirect, süresi dolmuş ve tekrar kullanılan kod reddedilir;
  ID token imza / audience / nonce / süre saldırıları gerçek ASP.NET OIDC istemcisinde reddedilir; ID token API'de
  kabul edilmez.
- Pano'da giriş (MFA ile) → API çağrısı → Rapor'da parolasız SSO, gerçek Chrome'da dört ayrı HTTPS origin üzerinde.
- Aynı TOTP kodu, aynı kurtarma kodu, aynı sıfırlama bağlantısı ve aynı refresh token eşzamanlı sunulduğunda
  **tam olarak bir** istek başarılı olur.
- Refresh token tekrar kullanımı tüm token ailesini ve grant'i iptal eder.
- Grant / oturum / kullanıcı / istemci iptali API erişimini bir sonraki istekte keser; kopyalanmış cookie'ler iki
  uygulamada ve sağlayıcıda çalışmaz.
- İmza anahtarı rotasyonunda eski token'lar geçerli kalır, istemciler yeni anahtarı izler, durum yeniden
  başlatmadan sonra korunur; acil iptal tüm grant'leri düşürür.
- Sağlayıcı veya veritabanı kesintisinde tüm yüzeyler 503 ile kapanır ve geri gelince aynı oturum / token'larla
  devam eder (bellek içi testte ve Compose konteynerlerinde).
- Log, denetim kaydı ve imajlarda parola, token, secret, TOTP sırrı, kurtarma kodu, e-posta adresi yoktur (pozitif
  kontrollü taramalarla).

## Süreçten notlar

Testlerin yakaladığı ve düzeltilen gerçek hatalardan bazıları (tam liste: `docs/implementation-progress.md`):

- Kütüphane, refresh sırasında eşzamanlı "redeem" hatasını yok sayıyordu → token uç noktasına atomik guard eklendi.
- Toplu iptal token satırlarının eşzamanlılık damgasını değiştirdiği için yarışı kazanan istek de başarısız
  olabiliyordu → yalnız authorization damgası değiştiriliyor.
- `alg=none` ID token yetim bir uygulama oturumu oluşturuyordu → açık imza doğrulaması ve oturum kaydının sırası.
- Konteyner imajında demo istemciler derlendiklerinden eski bir EF Core sürümü çözüyor ve açılmıyordu (yalnız
  Compose smoke testi yakaladı) → sürüm sabitlendi, yayın kontrolü eklendi.
- Veritabanı yeniden başladıktan sonra havuzdaki ölü bağlantı ilk girişi düşürüyordu (yine smoke testi yakaladı) →
  havuz temizliği, boşta bağlantı ömrü ve istemcide yeniden deneme.

## Kendiniz deneyin (yaklaşık 10 dakika)

```powershell
cd enterprise-identity-access-platform
./scripts/local-stack.ps1 up
```

Parolalar: `.local/seed/credentials.json`. Tarayıcının yerel sertifika uyarısı için `README.md`.

**SSO**
1. `https://pano.localhost:9444` → *Sign in with Halka ID* → `alice@halka.test` → *Allow*.
2. *Workspace* → *Add note*, *Load notes* (Pano API'yi sunucudan çağırır; durum kodu sayfada görünür).
3. `https://rapor.localhost:9445` → *Sign in with Halka ID*: parola sorulmaz, yalnız Rapor'un izin ekranı gelir.
   Rapor notları okuyabilir, yazmayı denediğinde `403` alır (yalnız okuma izni vardır).

**MFA**
4. `https://id.halka.localhost:9443/manage/mfa` → *Set up an authenticator app*: QR kodu bir kimlik doğrulama
   uygulamasıyla tarayın, kodu girin, kurtarma kodlarını saklayın.
5. Çıkış yapıp yeniden girin: parola + kod gerekir. Pano'da *Load sensitive notes* artık `200` döner (yalnız
   parolayla açılmış oturumda `403`).
6. `admin@halka.test` ile giriş: yönetim alanı MFA kaydı olmadan açılmaz.

**İptal**
7. `https://id.halka.localhost:9443/manage/apps` → Pano için *Withdraw access*. Pano sekmesini yenileyin: oturum
   kapanmıştır; Rapor çalışmaya devam eder. Pano'ya yeniden girişte parola sorulmaz ama izin yeniden istenir.
8. `/manage/sessions` → *Sign out everywhere*: Pano ve Rapor bir sonraki istekte oturumu düşürür.
9. Yönetici olarak `/admin/clients/rapor-web` → *Disable client*: Rapor'a giriş ve Rapor'un token'ları anında
   reddedilir; *Enable client* ile geri alınır.

**Makine istemcisi**
10. `./scripts/local-stack.ps1 machine`: `client_credentials` ile token alır, API'yi çağırır, izinli olmadığı
    uç noktada reddedildiğini gösterir (token değerleri maskelidir).

Kapatma: `./scripts/local-stack.ps1 down` (veri ve anahtarlar korunur).

## Sınırlar

Üretimde çalıştırılmadı, bağımsız denetimden geçmedi, OIDC uyumluluk paketi koşulmadı, tek instance, gerçek
e-posta ve federasyon yok. Tam liste: `docs/known-limitations.md`.
