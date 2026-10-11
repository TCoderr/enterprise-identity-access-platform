# Sonraki Adım

**Durum:** Aşama 1–10 tamam. Yerel kapıların tümü tek kaynak durumunda
(`sha256:15015539afab3692006971ed65611ddfaefc93154ce5320822f69e1e007e12c9`) geçti (kayıt A). Sonrasında iki
kozmetik kusur düzeltildi; **güncel kaynak** `sha256:47adc621657715d0d0a98ecad97e0a86f416a65a208a90a8f4a56e13a135573d`
(kayıt B) ve bunun üzerinde yalnız etkilenen kontroller koşuldu: tarayıcı testleri 13 / 13, UI araçları, UI ile
ilgili entegrasyon testleri, Release build, tarama, log adı kontrolleri. Birim, tam entegrasyon, Compose smoke,
yayın kontrolü ve `verify.ps1` paketi güncel kaynakta koşulmadı. Ayrıntı: `docs/final-verification.md`. Uzak CI
koşulmadı.

Bu depoda **commit, push, uzak CI veya dağıtım yapılmadı**. Bekleyen zorunlu iş yok.

## Kaynak değişirse

Kaynak veya betik değişirse eski sonuçlar geçersizdir. Tümünü yeniden koşmak için:

```powershell
cd "D:\Enterprise Identity & Access Management\enterprise-identity-access-platform"
./scripts/source-fingerprint.ps1
./scripts/verify.ps1                 # Docker ve kurulu Chrome gerekir
```

- 16 GB bellekli bu makinede, komşu konteynerler ve tarayıcı açıkken `verify.ps1` tek çağrıda bellek sınırına
  dayanıyor (smoke'un imaj derlemesinde boş bellek 0,4 GB'a indi; ilk koşu bu yüzden ortam tarafından
  durdurulmuştu). Bellek darsa kapılar tek tek, sırayla koşulabilir: `./scripts/test.ps1 -Project Unit|Integration|E2E
  -Configuration Release`, `npm run check` (`src/Halka.Iam/ui-tooling` içinde), `./scripts/scan.ps1`,
  `./scripts/smoke.ps1`. Smoke'tan sonra WSL belleği bir süre bırakmaz; sonraki ağır adımdan önce beklemek gerekir.
- `artifacts/verification/raw/` altındaki eski adlı loglar (`verify-tests-ntegration.log`) düzeltmeden önceki
  koşudan kalmadır; yeni koşular `verify-tests-integration.log` üretir.

## Sahibi isterse sonraki işler (hiçbiri başlatılmadı)

1. İlk commit ve (istenirse) uzak depo: yazar kimliği TCoderr olmalı. Push sonrası `.github/workflows/ci.yml`
   ilk kez gerçek bir CI'da koşar.
2. OpenID Foundation uyumluluk paketini yerel issuer ile koşmak (koşulmadı; iddia da yok).
3. `docs/known-limitations.md` içindeki üretim sertleştirme maddeleri.

## Dokunulmaması gerekenler

- Komşu ürünlerin konteynerleri ve portları (8443 / 8643 / 8843) bu projeyle ilgili değildir.
- `reset` komutu yıkıcıdır ve açık onay ister. Geliştirme yığınının `.local/` dizini şu an **yok** (yerel yığın
  hiç başlatılmadı; ilk `local-stack.ps1 up` üretir). Smoke kendi `.local-smoke` dizinini kullanır ve bitince siler.
