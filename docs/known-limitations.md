# Bilinen Sınırlar

Bu proje bir portföy / referans uygulamasıdır. Aşağıdakiler bilinçli kapsam dışıdır veya doğrulanmamıştır;
hiçbiri "yapıldı" sayılmamalıdır.

## Güvence ve sertifikasyon

- **OpenID Foundation uyumluluk (conformance) paketi çalıştırılmadı.** "OIDC certified" veya "standartla tam
  uyumlu" iddiası yoktur. Protokol davranışı OpenIddict 7.7.2'ye ve bu depodaki HTTP düzeyindeki testlere dayanır;
  kütüphanenin kendi testleri bu yapılandırmanın kanıtı değildir.
- Bağımsız güvenlik denetimi, sızma testi, DAST / fuzzing yapılmadı. Tarama betiği (`scripts/scan.ps1`) dar
  kapsamlıdır (anahtar / sır kalıpları, yazarlık terimleri, bilinen bağımlılık zafiyetleri); sıfır bulgu "güvenli"
  demek değildir.
- Uzak CI çalıştırılmadı (depo hiçbir yere gönderilmedi). `.github/workflows/ci.yml` yalnız yerelde eşdeğer
  komutlarla denenmiştir; yerel koşu uzak CI sonucu sayılmaz.

## Üretim sertleştirmesi

- **Tek instance.** Hız sınırlayıcılar ve anahtar halkası anlık görüntüsü süreç belleğindedir; birden çok
  kopyada paylaşılan sayaç, anahtar yenileme bildirimi ve Data Protection anahtar paylaşımı gerekir (uygulanmadı).
- Yük, dayanıklılık ve kapasite testi yapılmadı. Her istekte veritabanı okuması (oturum, rol, grant) ve her API
  isteğinde introspection bilinçli bir doğruluk / maliyet tercihidir; ölçeklenme davranışı ölçülmedi.
- HSM / KMS yok: protokol anahtarları veritabanında, Data Protection ile sarılı durur; Data Protection anahtarları
  yerel dizinde, bir sertifikayla sarılıdır. Bu anahtarlar kaybolursa TOTP secret'ları, protokol anahtarları, outbox
  içerikleri ve uygulama oturumları çözülemez.
- Anahtar rotasyonu elle tetiklenir (yönetim arayüzü); zamanlanmış otomatik rotasyon yok. "Önce yayınla, sonra
  imzala" ara durumu yok: JWKS'i uzun süre önbellekleyen ve bilinmeyen `kid` için yenilemeyen üçüncü parti
  istemciler rotasyondan sonra kısa süre doğrulama hatası alabilir (demo istemciler yeniler).
- Veritabanı yeniden başlatıldıktan sonra havuzda kalmış ölü bağlantılar için önlemler vardır (kesinti fark
  edildiğinde havuz temizliği, 60 sn boşta bağlantı ömrü, demo istemcilerde geçici hata yeniden denemesi). Kimlik
  sağlayıcıda açık transaction kullanıldığı için otomatik yeniden deneme yoktur: çok kısa bir yeniden başlatmadan
  hemen sonraki ilk istek 503 alabilir (durum değişmez, yeniden denenir).
- Yedekleme / geri yükleme, felaket kurtarma, sıfır kesintili sürüm geçişi tanımlanmadı.
- Gözlemlenebilirlik: yapılandırılmış JSON log ve `System.Diagnostics.Metrics` sayaçları vardır; OpenTelemetry
  dışa aktarımı, dağıtık izleme ve uyarı kuralları yoktur.
- Denetim kaydı veritabanında salt-eklemedir (runtime rolü değiştiremez / silemez) ancak kriptografik olarak
  zincirlenmemiş ve dışarıya aktarılmamıştır; veritabanı sahibi rolü değiştirebilir.
- TLS yalnız yerel CA ile; sertifika yenileme, HSTS preload, ters vekil / WAF yapılandırması kapsam dışı.

## Kimlik özellikleri

- **Gerçek e-posta / SMS yok.** Onay ve sıfırlama bağlantıları yerel özel dizine (`.local/mail-sink`) yazılır.
  Bu dizindeki dosyalar saklama (retention) işinin kapsamında değildir.
- Federasyon / sosyal giriş, SAML, LDAP / AD, SCIM, kurumsal dizin eşitlemesi yok.
- İkinci faktör yalnız TOTP + kurtarma kodlarıdır; WebAuthn / passkey, push, SMS yok. TOTP paylaşılan sır tabanlıdır
  ve oltalamaya dayanıklı değildir.
- Sızdırılmış parola listesi kontrolü, risk tabanlı kimlik doğrulama, cihaz güveni, CAPTCHA yok.
- Hesap silme / veri dışa aktarma (KVKK / GDPR süreçleri) ve çok kiracılı yapı yok.
- Desteklenen akışlar: authorization code + PKCE (S256), refresh token, client credentials. Device code, CIBA,
  PAR, DPoP / mTLS (sender-constrained token), dinamik istemci kaydı, pairwise subject, back-channel ve
  front-channel logout yok. Public (secret'sız) istemci tipi kayıt arayüzünde sunulmaz.
- Yalnız `response_mode=query`; `form_post` kapalıdır.
- Geçersiz yetkilendirme istekleri (yanlış `redirect_uri`, izin verilmeyen scope, PKCE eksikliği) istemciye
  yönlendirilmez; sağlayıcıda hata sayfası gösterilir (kütüphane davranışı, bilinçli olarak korunmuştur).
- Refresh token tekrar kullanımında tolerans yoktur: eşzamanlı refresh yapan (singleflight kullanmayan) bir
  istemci grant'ini kaybeder ve SSO ile yeniden alır.
- Zorunlu yeniden giriş (`prompt=login`, `max_age`) yeni bir merkezi oturum açar ve eskisini sonlandırır; bu,
  aynı tarayıcıdaki diğer uygulamaların oturumlarını da düşürür (SSO ile geri gelirler).
- ID token'lar iptal edilemez (5 dakika ömür).

## Arayüz ve erişilebilirlik

- Arayüz dili İngilizcedir; yerelleştirme yok.
- Erişilebilirlik: axe-core otomatik kuralları ve klavye ile giriş senaryosu otomatik sınanır; 360 / 768 / 1440 px
  ekran görüntüleri gözle incelendi (yeniden üretilen 88 görüntünün yalnız bir kısmı; hangileri olduğu
  `docs/final-verification.md` içinde). **Ekran okuyucu (NVDA / JAWS / VoiceOver) ile elle test yapılmadı.**
- Tablo başlığı genişliği yalnız erişilebilirlik testinin gezdiği 29 ekranda ölçülür; başlıklı tablosu olup bu
  testte gezilmeyen ekranlar (ör. `/manage/activity`) aynı ortak stil kuralını kullanır ama ayrıca ölçülmedi.
- Tarayıcı testleri yalnız masaüstü Chrome (kurulu sürüm, headless) ile koşar; Firefox, Safari ve mobil
  tarayıcılar denenmedi. Test tarayıcısı sertifikaları SPKI özetiyle kabul eder; gerçek kullanımda yerel CA'yı
  kullanıcı kendi tarayıcı profiline eklemeli ya da uyarıyı geçmelidir.
- `SameSite` davranışı gerçek Chrome ile sınanır; HTTP düzeyindeki test istemcisi `SameSite` modellemez.

## Test kapsamı

- Zaman yolculuğu yapan testler sahte saat kullanır; ASP.NET OIDC istemcisinin ID token süre doğrulaması gerçek
  saatle çalıştığı için bu tür senaryolar protokol düzeyindeki test istemcisiyle veya saat farkı verilmiş ayrı bir
  yığınla sınanır.
- Geçerli imzalı fakat yanlış issuer taşıyan ID token sağlayıcının anahtarı olmadan üretilemez; issuer kontrolü
  dolaylı sınandı (`docs/security-verification.md`).
- Hız sınırı pencereleri gerçek saatle çalışır; testler reddi ve boyut ayrımını doğrular, pencere yenilenmesini
  beklemez.
- Compose smoke testi yalnız Windows + Docker Desktop üzerinde koşturuldu; `scripts/local-stack.sh` aynı
  Compose dosyasını kullanır ancak Linux / macOS üzerinde koşturulmadı.
- Saklama (`RetentionWorker`) zamanlayıcı döngüsü ayrı test edilmedi; iş mantığı (`RetentionService`) test edildi.
- Final kapıları tek kaynak durumunda geçti, ancak `scripts/verify.ps1` tek çağrıda baştan sona koşulamadı: 16 GB
  bellekli geliştirme makinesinde ilk koşu bellek yetersizliğinden durduruldu, kalan kapılar aynı komutlarla tek
  tek koşuldu (`docs/final-verification.md`). Uzak CI hiç koşulmadı.
- Güncel kaynak, final kapılarının koşulduğu durumdan üç dosyayla ayrılır (stil dosyası, bir tarayıcı testi,
  `verify.ps1`). Bu durumda yalnız etkilenen kontroller koşuldu; birim, tam entegrasyon, Compose smoke, yayın
  kontrolü ve `verify.ps1` paketi yeniden koşulmadı.
- PowerShell betikleri için depoda otomatik test yoktur; `verify.ps1` log adı düzeltmesi depo dışı kontrol
  betikleriyle (tr-TR ve en-US, Windows PowerShell 5.1) doğrulandı.

## Yerel kurulum

- `reset` veya `.local/` dizininin silinmesi tüm anahtarları yeniden üretir: mevcut oturumlar, token'lar, MFA
  kayıtları ve demo parolaları geçersiz olur (veritabanı da sıfırlanır).
- Demo parolaları ve secret'lar kuruluma özel rastgele üretilir ve yalnız `.local/` altında durur.
