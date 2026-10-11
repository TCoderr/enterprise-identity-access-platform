# Uygulama İlerlemesi

Kaynak fingerprint'i: `./scripts/source-fingerprint.ps1`. Test sonuçları yalnız birlikte yazıldıkları fingerprint için geçerlidir.

## Aşama 0 — Başlangıç (2026-10-11)

- Çalışma dizini `D:\Enterprise Identity & Access Management` boştu, git deposu değildi; etkili ajan/depo talimat dosyası yok.
- Envanter: yerelde (komşu ürün klasörleri, kullanıcı klasörleri) ve public GitHub hesabında (19 depo) bağımsız IAM ürünü yok. Komşu ürünler (`Multi-Tenant SaaS Platform`, `Logistics & Shipment Tracking System`, `Etkinlik ve Bilet Satış Platformu`) yalnız listelendi, değiştirilmedi.
- Araçlar: .NET SDK 10.0.401 / runtime 10.0.12, Git 2.55, Node 24.18, npm 12.1, Docker Engine 29.8.2 + Compose v5.5.1, Chrome kurulu. `openssl`/`psql` PATH'te yok (gerekmedi: sertifikalar .NET API'siyle üretiliyor).
- Dolu portlar: 8443/8643/8843 (komşu ürünler) → kullanılmadı. Seçilen: 9443–9446 (geliştirme), 9453–9456 (smoke).
- Proje `enterprise-identity-access-platform/` altında oluşturuldu; `git init -b main` (commit yok).
- Kütüphane doğrulaması: OpenIddict 7.7.2 (Apache-2.0, 2026-10-10), kaynak kodu okunarak refresh/introspection davranışları doğrulandı (ADR-0001, ADR-0005).
- Bulgu: Windows'ta .NET 10 `*.localhost` adlarını çözmüyor → backchannel loopback yönlendirmesi (ADR-0009).

## Tasarım

`docs/01`–`09` ve `docs/adr/0001`–`0011` yazıldı. Tutarlılık gözden geçirmesi: token ömürleri, oturum/grant/token modeli, iptal politikası ve endpoint listesi 02/04/05/06 arasında karşılaştırıldı.

## Aşama 1 — Solution / Identity / oturum ✅

Kararlar
- Kimlik cookie'si yalnız `sub` + `sid` taşır; her istekte oturum, kullanıcı ve roller DB'den okunur.
- `SessionOptions` adı ASP.NET ile çakıştığı için `CentralSessionOptions`.
- Tek kullanımlık hesap token'ları Identity token provider'ı yerine kendi tablomuzda (hash + koşullu UPDATE): `TimeProvider` ile deterministik, gerçekten tek kullanım.
- UI varlıkları assembly'ye gömülü (`/assets/*`): `dotnet run`, test ve container'da aynı.
- Parola sıfırlama sayfaları Aşama 9 yerine şimdi yazıldı (bağlanmamış bağlantı kalmasın); test/sertleştirmesi Aşama 9'da.
- Test çalıştırıcısı: xUnit v3 + Microsoft Testing Platform (`global.json` → `test.runner`).

Dosyalar: `src/Halka.Shared`, `src/Halka.Iam` (Data, Identity, Sessions, Revocation, Audit, Mail, Ops, Api, Pages), `src/Halka.Migrator`, `tools/Halka.LocalInit`, `tests/Halka.TestKit`, `tests/Halka.UnitTests`, `tests/Halka.IntegrationTests/Stage1`. Migration: `InitialIdentityAndSessions`.

Kabul kapısı

| Kabul | Test |
|---|---|
| Generic credentials / lockout | `Login_GenericError_IsIdenticalForUnknownWrongPasswordLockedOutAndDisabled` |
| Session fixation guard | `Login_RotatesSession_PreviousSessionOfTheBrowserIsEnded` |
| Logout sonrası yakalanmış cookie reddi | `Session_CapturedCookieAfterLogout_IsDenied` |
| Disabled kullanıcı reddi | `Session_DisabledUser_IsDeniedOnNextRequestAndCannotSignInAgain` |
| Private sink | `MailSink_IsNotReachableOverHttp_AndTokensAreStoredOnlyAsHashes`, `Signup_*` |
| Kısıtlı roller | `Admin_AreaRequiresAdministrativeRole_AndRoleRemovalAppliesImmediately`, `DbRoles_*` |
| CSRF, open redirect, IDOR | `Csrf_*`, `ReturnUrl_*`, `Idor_*` |
| Test guard | `TestGuard_WrongTarget_IsRefusedAndNothingIsWritten` |

Komutlar ve sonuç

| Komut | Exit | Toplam | Pass | Fail | Skip |
|---|---|---|---|---|---|
| `./scripts/test.ps1 -Project Unit` | 0 | 30 | 30 | 0 | 0 |
| `./scripts/test.ps1 -Project Integration` | 0 | 28 | 28 | 0 | 0 |

Fail → kök neden → düzeltme
- `Login_ValidCredentials...`: beklenen `Cache-Control: no-store`, gerçek `no-store, no-cache` (antiforgery ekliyor) → **test beklentisi** düzeltildi (`Contains`).
- `Session_UserCanRevokeOwnOtherSession...`: sabit sahte saatte iki oturumun `created_at` değeri eşit, sıralama belirsiz → **test fixture** (girişler arasında saat 1 sn ilerletildi).
- İlk koşuda 21 hata: test tarayıcısı form `action`'ını mutlak URL'ye çevirmiyordu → **test fixture** düzeltildi.

## Aşama 2 — Docker / HTTPS / anahtar / CI temeli ✅ (IAM kapsamı; diğer servisler eklendikçe smoke genişler)

Kararlar
- Tek `deploy/Dockerfile` (`PROJECT` build arg), taban imajlar sabit: `sdk:10.0.401`, `aspnet:10.0.12`; restore `--locked-mode`.
- Sırlar Compose `secrets` (dosya) ile servis bazında mount edilir; ortam değişkeninde sır yok.
- Sağlık kontrolü uygulamaya gömülü (`--healthcheck`): image'da curl/shell aracı gerekmez.
- Smoke ayrı, atılabilir Compose projesinde (`halka-smoke`, `.local-smoke`, 9453+) koşar; geliştirme stack'ine dokunmaz.
- DB erişilemezse 503 (statik sayfa), cookie silinmez, erişim verilmez (`UnavailableExceptionHandler`).

Kabul kapısı (`./scripts/smoke.ps1`, exit 0)

| Kabul | Kanıt |
|---|---|
| Boş init/up ve restart | `empty init + up: ok`, `down + up: ok`, `Session_Accounts_AndKeys_SurviveARestart` |
| Secure cookie, HTTPS, host filtresi | `Stack_IsReady_OverHttpsWithTheLocalCa_AndCookiesAreSecure`, `HostHeader_OtherThanThePublicHost_IsRejected` |
| Non-root, read-only, cap drop | `Containers_RunAsNonRoot_WithReadOnlyRootAndNoCapabilities` |
| DB down/up | `DatabaseOutage_FailsClosed_...`, `DatabaseRecovery_RestoresReadiness...` |
| Image/log'da sır yok (+ pozitif canary) | `Images_ContainNoSecretOrPrivateKeyMaterial`, `Scanner_PositiveControl_FindsEveryPlantedLeak`, `Logs_ContainNoSecretValues` |
| Anahtar depolama restart tutarlı | Restart öncesi cookie restart sonrası çözülüyor (aynı DP key ring) |
| Container DNS ile client discovery | **Aşama 3/4'te** Pano/Rapor/API eklendiğinde smoke'a eklenecek (ertelenen alt kapı) |

| Komut | Exit | Faz sonuçları |
|---|---|---|
| `./scripts/smoke.ps1` | 0 | up 6/6, restarted 2/2, db-down 1/1, db-recovered 1/1 (skip 0) |

Fail → kök neden → düzeltme
- Script'ler ilk koşuda durdu: Windows PowerShell 5.1, yönlendirilen native stderr'i hata sayıyor → **script** (`Invoke-Native`: akışlar birleştirilir, exit code belirler).
- Smoke fazları exit 3: test exe'si MTP CLI'sini konuşmuyordu → `UseMicrosoftTestingPlatformRunner=true`.
- `HostHeader_...`: `HttpClient` TLS sunucu adını Host header'ından türetiyor → **test fixture** (ham `SslStream` ile gönderim).

CI: `.github/workflows/ci.yml` yazıldı; push yapılmadığı için **uzakta koşmadı**.

## Aşama 3 — Client registry / scope / OIDC code flow ✅

Kararlar
- OpenIddict server: yalnız `authorization_code` (+PKCE S256 zorunlu), `refresh_token`, `client_credentials`; `response_mode=query`; reference access/refresh token; `RefreshTokenReuseLeeway = null`.
- Authorize ve end-session uç noktaları Razor Page (pass-through), token/userinfo minimal API.
- Protokol anahtarları DB'de DP ile sarılı; `ProtocolKeyRing` + options cache yenileme (ADR-0008).
- Client secret grace ve disabled kontrolü `HalkaApplicationManager.ValidateClientSecretAsync` içinde; hash/karşılaştırma kütüphanede.
- Workspace API: `OpenIddict.Validation` + introspection; IAM erişilemezse 503.
- Demo BFF: token'lar `app_sessions` tablosunda DP ile şifreli; cookie yalnız oturum kimliği + görüntü claim'leri.

Kütüphane bulguları (testle ortaya çıktı, tasarıma işlendi)
- OpenIddict istek doğrulama hatalarını (izinsiz scope, PKCE eksik, kayıtsız redirect) client'a **redirect etmez**, kendi sayfasında 400 gösterir; yalnız pass-through hataları (`login_required`, `consent_required`, `access_denied`) redirect edilir.
- Introspection'a ID token gönderilince sunucu `unsupported_token_type` hatası döner ve doğrulama kütüphanesi bunu `server_error` sayar → API 503 dönüyordu. RFC 7662 §2.2'ye uygun olarak yanıt `active:false` olarak normalleştirildi (`NormalizeUnsupportedTokenTypeResponse`); API artık 401 döner.
- ASP.NET Core OIDC handler'ı code flow'da token endpoint'inden gelen ID token için imzayı **zorunlu tutmaz** (`RequireSignedTokens=false`, spec gereği TLS'e güvenir): `alg=none` token `TokenValidated` olayına kadar ulaşıyordu. Demo istemciye `OnTokenResponseReceived` içinde kütüphaneyle açık doğrulama eklendi (RS256 allowlist, imza zorunlu, issuer, audience) ve app oturumu kaydı tüm doğrulamalar bittikten sonraya (`OnTicketReceived`) taşındı.

Kabul kapısı → test

| Kabul | Test |
|---|---|
| Code + PKCE başarı | `Code_WithPkce_IssuesOpaqueAccessTokenAndSignedIdToken`, `Pano_SignInThroughTheIdentityProvider_ThenCallsTheApi` |
| Yanlış verifier / client / redirect / reuse / expiry | `Code_WrongOrMissingVerifier_IsRejected`, `Code_RedeemedByAnotherClient_OrWithWrongSecretOrRedirectUri_IsRejected`, `Code_SecondUse_IsRejected_AndTheTokensOfTheFirstUseAreRevoked`, `Code_Expired_IsRejected`, `Redirect_AnythingButTheExactRegisteredUri_IsRefusedWithoutRedirecting` (11 varyant) |
| Tampered ID / access | `IdToken_WithModifiedSignature/Payload/AlgNone_IsRejected`, `IdToken_SignedByAnotherKey_...`, `Api_WithoutToken_OrWithGarbageOrTamperedToken_Returns401WithBearerChallenge` |
| Yanlış issuer / audience | `IdToken_SignedByAnotherKey_WithTheSameKeyId_OrAnotherIssuer_IsRejected`, `IdToken_IssuedForAnotherClient_IsRejected_WrongAudience`, `Api_RejectsATokenThatWasNotIssuedForThisAudience`, `IdToken_Expired_IsRejectedByTheClient`, `IdToken_FromAnotherAuthorizationRequest_IsRejected_NonceMismatch` |
| ID token API reddi | `Api_RejectsAnIdTokenPresentedAsBearer` |
| Least scope | `Client_CannotObtainAScopeItIsNotAllowed`, `Api_InsufficientScope_Returns403WithStandardChallengeAndProblemDetails` |
| Discovery / JWKS | `Discovery_AdvertisesExactlyTheSupportedProtocolSurface`, `Jwks_PublishesOnlyPublicSigningKeyMaterial` |
| State/nonce (gerçek istemci) | `Pano_Callback_WithoutState_WithForeignState_OrReplayed_IsRejectedByTheClient` |

Sınır: Geçerli imzalı ama yanlış issuer'lı ID token üretilemez (anahtar bizde); issuer kontrolü saldırgan anahtarıyla yeniden imzalanmış token ve discovery issuer eşitliği ile sınandı.

## Aşama 4 — Consent ve iki uygulama SSO ✅

Kararlar
- Consent kararı yalnız antiforgery korumalı POST ile; GET sorgusundaki karar yok sayılır.
- `prompt=login`/`max_age=0`: reauth cookie'si istek özeti + zaman + **o anki oturum kimliği** taşır; devam için farklı (yeni) oturum şarttır.

| Kabul | Test |
|---|---|
| A login → B kimlik bilgisiz SSO, B consent yine istenir | `Sso_SignedInToPano_ThenRapor_NeedsNoCredentials_ButStillAsksForRaporsConsent`, E2E `Pano_Login_ThenApi_ThenRapor_SingleSignOn_InARealBrowser` |
| prompt none / login / max_age | `Prompt_None_ReturnsLoginRequired_ConsentRequired_OrACode`, `Prompt_Login_CannotBeSatisfiedByAnExistingSsoCookie`, `MaxAge_OlderSession_MustAuthenticateAgain_AndAuthTimeIsReported` |
| Forged consent CSRF | `Consent_ForgedDecision_WithoutOrWithForeignAntiForgeryToken_GrantsNothing` |
| Yanlış app scope | `Client_CannotObtainAScopeItIsNotAllowed` (rapor: write, email) |
| Metadata'da secret yok | `ClientSecrets_AreStoredHashed_AndNeverExposedByPublicEndpoints` |
| İki origin gerçek tarayıcı | E2E (Chrome, SPKI pin): cookie'ler host-only/Secure/HttpOnly/Lax, web storage boş, harici istek yok |
| UserInfo / claim minimizasyonu, consent revoke | `UserInfo_AndIdToken_OnlyContainClaimsOfGrantedScopes`, `Consent_Revoked_KillsTheClientsTokensImmediately_AndConsentIsAskedAgain` |

## Aşama 5 — MFA ve admin step-up ✅

Kararlar
- TOTP: Otp.NET, ±1 adım; timestep koşullu UPDATE ile tek kullanım. Recovery code: SHA-256 (kullanıcı tuzlu), koşullu UPDATE.
- Pending challenge ayrı cookie (`__Host-halka-mfa`), hiçbir şema okumaz; deneme sınırı DB'de (5) + hesap bazlı bellek içi limit.
- Step-up: MFA'lı hesap için yalnız ikinci faktör; MFA'sız hesap için parola. Admin alanı MFA kaydı + MFA'lı oturum ister (`StepUpPageFilter`).
- Yardımcı sınıf adı `TotpCodes` (Otp.NET `Totp` ile çakışmasın).

| Kabul | Test |
|---|---|
| Geçerli / geçersiz / skew / expired challenge | `Login_WithMfa_PasswordAloneGivesNoSession_UntilAValidCode`, `Totp_ClockSkewOfOneStepIsAccepted_TwoStepsIsNot`, `Challenge_Expired_CannotBeCompleted`, `Challenge_AttemptLimit_ForcesTheUserBackToThePassword` |
| Paralel aynı TOTP tek kabul | `Totp_ParallelSameCode_IsAcceptedExactlyOnce` (servis: 8 eşzamanlı; HTTP: 2 tarayıcı) |
| Recovery paralel tek kabul, eski kod reddi | `Recovery_CodeSignsInOnce_ParallelUseSucceedsOnce_AndIsReportedWithoutOtp`, `Recovery_Regenerate_InvalidatesEveryOldCode` |
| Disable/reset reauth | `DisableAndRegenerate_NeedARecentSecondFactor_AStaleSessionIsNotEnough`, `Enrollment_NeedsARecentPassword_ForAccountsWithoutMfa` |
| Admin bypass yok | `Admin_WithoutMfa_CannotOpenTheAdministrationArea_AndCannotBypassIt`, `Admin_WithMfa_NeedsTheSecondFactorAtEverySignIn`, `StepUp_PasswordIsNotAcceptedForAccountsWithMfa_AndReturnUrlMustBeLocal` |
| Secret at-rest, tek gösterim | `Enrollment_IsOnlyActivatedByAValidCode_AndTheSecretIsProtectedAtRest` |

Not: `Admin_AreaRequiresAdministrativeRole...` (Aşama 1) admin için MFA zorunluluğu geldiği için MFA'lı admin hesabıyla güncellendi (gereksinim değişikliği; assertion'lar aynı).

Komutlar ve sonuç (Aşama 3–5 sonu)

| Komut | Exit | Toplam | Pass | Fail | Skip |
|---|---|---|---|---|---|
| `./scripts/test.ps1 -Project Unit` | 0 | 62 | 62 | 0 | 0 |
| `./scripts/test.ps1 -Project Integration` | 0 | 105 | 105 | 0 | 0 |
| `./scripts/test.ps1 -Project E2E` | 0 | 3 | 3 | 0 | 0 |

Fail → kök neden → düzeltme (özet)
- Scope/PKCE reddi testleri `error` parametresi bekliyordu → kütüphane davranışı (redirect yok) → **test beklentisi** düzeltildi.
- `Api_RejectsAnIdTokenPresentedAsBearer`: 500/503 → **uygulama** (introspection normalizasyonu + API hata eşlemesi).
- `IdToken_WithAlgNone_IsRejected`: oturum satırı oluşuyordu → **uygulama** (açık imza doğrulaması, oturum kaydı `OnTicketReceived`).
- E2E: iki "Sign out" düğmesi → **uygulama/UI** (onay düğmesi "Sign out of Halka ID").
- `TokenValidationParameters.TimeProvider` yok → süresi dolmuş ID token testi, IAM saati 11 dk geride ayrı yığınla gerçek istemci üzerinden yapıldı.

## Aşama 6 — Refresh token, iptal ve global logout ✅

Kararlar
- Refresh: `SetRefreshTokenReuseLeeway(null)` + token uç noktasında kendi atomik guard'ımız (`TryRedeemAsync`); kaybeden istek ve sıralı tekrar kullanım aynı sonuca gider: grant + aile iptal (ADR-0005).
- Toplu iptal authorization satırının eşzamanlılık damgasını değiştirir, token satırlarınınkini değiştirmez; token yazımı sırasında çakışma olursa yanıt standart OAuth hatasıdır.
- Demo BFF: sunucu taraflı uygulama oturumu, oturum başına singleflight refresh, her korumalı istekte sağlayıcıda durum doğrulaması (önbellek yok), yerel çıkışta kendi token'larını revocation uç noktasıyla iptal.
- Kesinti: API ve BFF fail-closed 503 (`Retry-After`), "geçersiz token" ile "doğrulanamadı" ayrımı.

| Kabul | Test |
|---|---|
| Eşzamanlı refresh / reuse aile etkisi | `Refresh_ParallelUseOfTheSameToken_RotatesExactlyOnce_AndTheFamilyEndsRevoked` (10 tur, tam 1 başarı), `Refresh_ReuseOfARotatedToken_RevokesTheWholeFamilyAndTheGrant`, `Bff_ConcurrentRequests_RefreshOnce_SingleFlight_AndNeverLookLikeTokenReuse` |
| Grant / kullanıcı / uygulama iptali anında API reddi | `Revoke_Grant_DeniesTheApiImmediately_OtherClientAndSessionUnaffected`, `Revoke_UserDisabled_EndsSessionsAndTokensAtOnce_AndBlocksEveryWayBackIn`, `Revoke_ClientDisabled_KillsItsTokensAndBlocksAllOfItsEndpoints_OtherClientsContinue` |
| Global logout sonrası çalınmış A/B cookie reddi | `GlobalLogout_EndsEveryApplicationSession_CapturedCookiesOfBothAppsAndTheProviderAreDenied`, E2E `SessionCookie_CopiedIntoAnotherBrowser_StopsWorkingAfterLogout` |
| Logout redirect kurcalama reddi | `EndSession_ForgedRedirect_IsRefused_AndLogoutNeedsAConfirmedPost` |
| Kesintide fail-closed | `Outage_IdentityProviderDown_ApiAndBffFailClosed_ThenRecoverWithTheSameTokensAndKeys` |

Fail → kök neden → düzeltme
- Paralel refresh'te bazen hiç `200` çıkmıyordu → toplu iptal token satırlarının damgasını değiştiriyordu, kazanan istek kendi yazımında çakışıyordu → **uygulama** (yalnız authorization damgası değişir; `ConcurrencyException` → OAuth hatası). 4 tam koşuda kararlı.
- BFF yerel çıkış token iptal etmiyordu → revocation adresi `AdditionalData` içinde aranıyordu → **uygulama** (`configuration.RevocationEndpoint`).
- Sabit sahte saatte `created_at` sıralaması belirsiz → **test fixture** (deterministik seçim).

## Aşama 7 — Client credentials, secret ve anahtar yaşam döngüsü ✅

Kararlar
- Makine istemcisi: yalnız `client_credentials`, kimlik scope'u / ID token / refresh token yok; token grant'siz, client'a bağlı.
- Secret rotasyonu: yeni secret bir kez gösterilir; önceki secret `client_secrets` tablosunda `not_after` ile grace penceresi boyunca kabul edilir; "grace yok" seçeneği eski girişleri de kapatır.
- Protokol anahtarları `protocol_keys` tablosunda, Data Protection ile sarılı; durumlar Active → Retiring → Retired, acil durumda Revoked; kullanım başına tek aktif anahtar filtreli benzersiz indeksle (ADR-0008).
- Demo istemciler bilinmeyen `kid` için JWKS'i yeniler ve yenileme bitene kadar (en çok 3 sn) bekler.

| Kabul | Test |
|---|---|
| Yanlış kimlik bilgisi, kullanıcı token'ı yok, yanlış scope | `Machine_ClientCredentials_YieldsAClientToken_WithoutUserClaimsIdTokenOrRefreshToken`, `Machine_WrongCredentials_AndScopesOutsideItsRegistration_AreRefused`, `Machine_CannotStartUserFlows_AndWebClientsCannotUseClientCredentials` |
| Rotasyonda eski / yeni pencere | `ClientSecret_Rotation_OldSecretWorksOnlyDuringTheGraceWindow`, `ClientSecret_RotationWithoutGrace_StopsTheOldSecretAtOnce_IncludingEarlierGraceEntries` |
| Özel anahtar JWKS'te yok; yeni `kid`, eski token doğrulaması; kalıcılık | `Jwks_PublishesOnlyPublicSigningKeyMaterial`, `Keys_SigningRotation_NewTokensUseTheNewKey_OldTokensStayValid_ClientsFollow_AndStateSurvivesARestart`, `Keys_Retire_IsOnlyPossibleAfterTheOverlap_AndThenRemovesTheKey`, `Keys_EncryptionRotation_KeepsExistingReferenceTokensReadable`, `Keys_AtMostOneActiveKeyPerUse_IsEnforcedByTheDatabase_EvenForConcurrentRotations`, `Keys_EmergencyRevoke_RemovesTheKeyImmediately_RevokesAllGrants_AndKeepsCentralSessions` |
| Devre dışı makine istemcisi | `Machine_Disabled_TokenRequestsFail_AndIssuedTokensStopWorking` |

Fail → kök neden → düzeltme
- Rotasyondan sonra Pano girişi yeni `kid` ile başarısız → `RequestRefresh()` arka planda çalışıyor → **uygulama** (yenileme tamamlanana kadar sınırlı bekleme).
- Anahtar rotasyonu testi koşu sırasına bağlıydı → **test** (sıra bağımsız hale getirildi).

## Aşama 8 — Hesap / yönetim / UI tam iş akışları ✅

Kararlar
- Yönetim rolleri: PlatformAdmin (hepsi + rol), SecurityAdmin (kullanıcı, oturum, grant, denetim, anahtar), ApplicationAdmin (client, scope). Hassas işlemler `[RequireStepUp]` ile taze ikinci faktör ister.
- Son PlatformAdmin koruması: advisory lock + sayım + değişiklik tek transaction.
- Denetim kaydı etkilenen hesabı `user=<id>` olarak içerir (kullanıcıya göre aranabilir); e-posta / IP içermez.
- UI araçları (`src/Halka.Iam/ui-tooling`): TypeScript ile JS tip denetimi, ESLint, `node --test`. Tarayıcıya giden paket / derleme adımı yoktur; "prod build" Release yayınıdır, "component" testleri sunucuda render edilen sayfaların testleridir (`UiRenderTests`).
- Tasarım / erişilebilirlik için harici bir "skill" paketi kurulmadı; tasarım depoda yazıldı (`docs/07-ui-design.md`, `design/preview.html`).

| Kabul | Test |
|---|---|
| Component / build / E2E | `Ui_AnonymousPages_AreWellFormed`, `Ui_AccountPages_SecondFactorPages_AndDemoClients_AreWellFormed`, `Ui_AdministrationPages_AreWellFormed`; `npm run check`; E2E 9 senaryo |
| Rol düşürme / son yönetici yarışı | `Admin_RoleChange_ThroughTheUi_NeedsPlatformAdmin_AndDemotionAppliesOnTheNextRequest`, `LastAdmin_ConcurrentDemotionAndDisable_AlwaysLeavesOneActivePlatformAdmin` |
| Sahiplik / IDOR | `Admin_SessionAndGrantRevocation_IsBoundToTheAccountInTheRoute`, `Account_ConnectedApps_AndActivity_ShowOnlyOwnData_AndWithdrawingAccessKillsTokens` |
| Mobil klavye | E2E `Keyboard_SignIn_OnAPhoneSizedViewport_WorksWithoutAPointer`, `A11y_KeyScreens_HaveNoAxeViolations_AndReflow_AtThreeWidths` (30 ekran × 3 genişlik, axe 0 ihlal) |
| Secret tek gösterim | `Admin_ClientRegistration_ShowsTheSecretOnce_AndRotationWorksThroughTheUi` |
| Çıkıştan sonra önbellek temiz | E2E `NormalUser_CannotReachAdministration_AndLoggedOutPagesAreNotServedFromCache` |

Fail → kök neden → düzeltme
- 360 px'te yatay taşma (uzun e-posta, tablo hücreleri, grid min-width) → **uygulama/CSS**.
- Klavye testi giriş alanına ulaşamıyordu → `autofocus` odak sırasını bozuyordu → **uygulama** (kaldırıldı).
- npm `.cmd` kısayolları yol içindeki `&` yüzünden bozuluyordu → **ortam** (betikler node giriş noktalarını doğrudan çağırır).
- Görsel incelemede bitişik blokların dikey boşlukları → **uygulama/CSS** (ritim kuralları).

Komutlar ve sonuç (Aşama 6–8 sonu)

| Komut | Exit | Toplam | Pass | Fail | Skip |
|---|---|---|---|---|---|
| `./scripts/test.ps1 -Project Unit` | 0 | 62 | 62 | 0 | 0 |
| `./scripts/test.ps1 -Project Integration` | 0 | 145 | 145 | 0 | 0 |
| `./scripts/test.ps1 -Project Integration -Filter '--filter-class','*UiRenderTests'` | 0 | 3 | 3 | 0 | 0 |
| `./scripts/test.ps1 -Project E2E` | 0 | 9 | 9 | 0 | 0 |
| `npm run check` (ui-tooling) | 0 | — | — | — | — |

## Aşama 9 — Kurtarma / operasyon / sertleştirme ✅

Kararlar
- Parola sıfırlama: bağlantı tek kullanımlık (koşullu UPDATE) ve 30 dk; yeni istek eskisini geçersiz kılar; zayıf parola bağlantıyı tüketmez; başarıda tüm oturum ve grant'ler iptal, ikinci faktör korunur, kimse otomatik oturum açmaz.
- Saklama (`RetentionService` / `RetentionWorker`): önce zaman aşımına uğramış oturumlar kapatılır (grant iptali), sonra yalnız kullanılamaz kayıtlar silinir; audit silinmez.
- Metrikler (`IamMetrics`, `System.Diagnostics.Metrics`): etiketler sabit küçük kümelerden; kullanıcı / client / token kimliği etiket olmaz.
- Veritabanı kesintisi: sayfalar statik 503, protokol uç noktaları 503 + OAuth hata nesnesi, `/api` problem+json; refresh token tüketilmez.
- Havuz hijyeni: kesinti fark edildiğinde (istek, hazır olma kontrolü, outbox worker) boşta bağlantılar atılır; boşta bağlantı ömrü 60 sn; demo istemci deposunda geçici hata yeniden denemesi.
- Demo istemciler kendi veritabanları ulaşılamadığında da 503 ile kapanır (önceden 500).
- Tarama: `scripts/scan.ps1` (pozitif kontrollü); tüm kapılar tek kaynak durumunda: `scripts/verify.ps1`.
- Final kapı 4 için gerçek tarayıcı senaryoları genişletildi (MFA'lı SSO + taze giriş, tarayıcıda iptal, client devre dışı / secret rotasyonu, IDOR).

Dosyalar: `src/Halka.Iam/Ops/Telemetry.cs`, `Ops/UnavailableExceptionHandler.cs` (+`StorePool`), `Ops/Health.cs`, `src/Halka.Shared/StoreFailures.cs`, `src/Halka.DemoClient` (yeniden deneme, hazır olma kontrolü, 503 ara katmanı), `tests/Halka.TestKit/TcpRelay.cs`, `tests/Halka.IntegrationTests/Stage9/*`, `tests/Halka.E2E/RevocationAndLifecycleBrowserTests.cs`, `tests/Halka.Smoke` (SSO, makine, DB/OP kesinti fazları), `scripts/scan.ps1`, `scripts/verify.ps1`, `README.md`, `THIRD-PARTY-NOTICES.md`.

| Kabul | Test |
|---|---|
| Sıfırlama token'ı: tek kullanım / süre / eşzamanlılık / iptal politikası | `PasswordResetTests` (8), `OneTimeLinkExpiryTests` (2) |
| Worker kurtarma | `OutboxTests` (5): paralel lease, çökmüş worker + fencing, backoff + DLQ, sink geri gelince tek teslim, worker döngüsü |
| Token log'da yok, metrikte PII yok | `Logs_AndAudit_ContainNoCredentialTokenOrPersonalData`, `Metrics_CountSecurityEvents_WithFixedLowCardinalityTagsOnly` |
| Kesinti durumları, hata standardı uyumu | `DatabaseDown_EverySurfaceFailsClosedWithAStandard503_ThenRecoversWithTheSameSessionsAndTokens`; smoke `db-down`, `db-recovered`, `op-down`, `op-recovered` |
| Dışa sızıntı yok | E2E dış istek kaydı boş; CSP; `Health_OpenApi_AndSecurityHeaders_ArePresent` |
| Hız sınırı boyutları | `RateLimitTests` (6) |
| Saklama | `Retention_RemovesOnlyDeadRecords_InStages_AndNeverTheAuditLogOrLiveState` |
| Migration yükseltme / idempotent script | `MigrationUpgradeTests` (2) |

Fail → kök neden → düzeltme
- Outbox / retention testlerinde zaman eşitliği → PostgreSQL mikrosaniye hassasiyeti → **test beklentisi** (saklanan hassasiyete yuvarlama).
- DB kesintisinde `/connect/token` HTML döndürüyordu → istisna ara katmanı isteğin yolunu hata yoluna çevirdiği için yol kontrolü hiç eşleşmiyordu (`/api` için de) → **uygulama** (`IExceptionHandlerPathFeature`).
- **Smoke:** Pano / Rapor konteynerleri açılmıyordu (`FileNotFoundException: Microsoft.EntityFrameworkCore 10.0.12`) → kitaplık 10.0.12'ye derleniyor, uygulama grafiği sağlayıcı paketin istediği 10.0.4'ü çözüyordu; testler IAM üzerinden doğru sürümü aldığı için görmedi → **uygulama/paket** (`Microsoft.EntityFrameworkCore.Relational` açık referans, lock dosyaları yenilendi, `verify.ps1` yayın kontrolü).
- **Smoke:** DB kesintisinde Pano 500 dönüyordu → kendi deposunun ulaşılamaması ele alınmıyordu → **uygulama** (503, cookie korunur).
- **Smoke:** OP geri geldikten sonra Rapor'a ilk giriş 503 → daha önceki DB yeniden başlatmasından kalan ölü havuz bağlantısı (`57P01`) → **uygulama** (yeniden deneme stratejisi, havuz temizliği, boşta ömür).
- Doğrulama ekran görüntülerinde test hesabının TOTP anahtarı görünüyordu → **test altyapısı** (anahtar, QR, kurtarma kodu ve secret alanları maskelenir).

Komutlar ve sonuç (Aşama 9 sonu, ara durumlar)

| Komut | Exit | Toplam | Pass | Fail | Skip |
|---|---|---|---|---|---|
| `./scripts/test.ps1 -Project Unit` | 0 | 62 | 62 | 0 | 0 |
| `./scripts/test.ps1 -Project Integration` | 0 | 173 | 173 | 0 | 0 |
| `./scripts/test.ps1 -Project Integration -Filter '--filter-class','*MigrationUpgradeTests'` | 0 | 2 | 2 | 0 | 0 |
| `./scripts/test.ps1 -Project E2E` | 0 | 9 | 9 | 0 | 0 |
| `./scripts/test.ps1 -Project E2E -Filter '--filter-class','*RevocationAndLifecycleBrowserTests'` | 0 | 4 | 4 | 0 | 0 |
| `./scripts/smoke.ps1` (4. koşu; ilk üçü yukarıdaki hataları buldu) | 0 | 16 | 16 | 0 | 0 |
| `./scripts/scan.ps1` | 0 | 12 kontrol | 12 | 0 | — |

## Aşama 10 — Final kapıları / belgeler ✅ (yerel kapılar; ilk koşu kesildi, devamı aşağıda)

- Belgeler yazıldı: `README.md`, `THIRD-PARTY-NOTICES.md`, `docs/security-verification.md`, `docs/revocation-matrix.md`, `docs/final-verification.md`, `docs/known-limitations.md`, `docs/portfolio-summary.md`; `docs/04`, `docs/09`, ADR-0005 ve ADR-0008 uygulamayla eşitlendi.
- `./scripts/verify.ps1` (tüm kapılar, tek kaynak durumu) başlatıldı. Fingerprint `sha256:15015539afab3692006971ed65611ddfaefc93154ce5320822f69e1e007e12c9` (248 dosya).
- Tamamlanan: kilitli restore (0), Release build (0 uyarı / 0 hata), Unit 62 / 62, Integration 175 / 175 (skip 0).
- **Kesildi:** tarayıcı testleri sırasında sistem belleği kritik düzeye indi ve çalışma ortamı arka plan komutunu durdurdu. Komut kendiliğinden yeniden başlatılmadı. Sonrasında: fingerprint değişmedi, geride test süreci / konteyner yok, boşta kalan derleme sunucuları kapatıldı.
- Bu fingerprint için koşulmamış kapılar: tarayıcı testleri (13), UI araçları, yayın kontrolü, Compose smoke. Bunların önceki kaynak durumlarındaki son sonuçları yeşildir; aradaki farklar `docs/final-verification.md` içinde listelidir.
- Maskeden önce alınmış MFA kayıt ekranı görüntüleri (`iam-mfa-enroll-*.png`) silindi.

### Aşama 10 devamı — eksik kapılar aynı fingerprint üzerinde tamamlandı (2026-10-11, 09:42–09:54)

- Başlangıç: git durumu "No commits yet on main", tüm dosyalar izlenmiyor; fingerprint `sha256:15015539afab3692006971ed65611ddfaefc93154ce5320822f69e1e007e12c9` (248 dosya); boş bellek 3,8 GB; `halka*` / Testcontainers konteyneri yok; komşu ürün konteynerleri çalışıyor (dokunulmadı).
- Karar: kaynak ve betik değiştirilmedi (kozmetik `-creplace` düzeltmesi fingerprint'i değiştireceği için ertelendi). `verify.ps1` tek çağrıda koşulmadı; içindeki komutların aynısı tek tek, sırayla ve her ağır adımdan önce boş bellek ölçülerek koşuldu. Yardımcı sarmalayıcılar proje dışındaki geçici dizindedir. Tarayıcı testleri zaten tek koleksiyonda sıralı koşar; kapsam ve assertion'lar azaltılmadı.
- Birim / entegrasyon bu oturumda ikinci kez koşulmak istendi; smoke sonrası boş bellek 1,4 GB (1,8 GB eşiğinin altı) olduğu için başlatılmadı ve tekrar denenmedi. 04:13 koşusundaki sonuçları aynı fingerprint içindir.
- Ekran görüntüleri (88) maskeli olarak yeniden üretildi; MFA kayıt ekranında QR ve kurulum anahtarı kapalı (gözle doğrulandı). `artifacts/verification` altında token / secret / parola / `otpauth` / özel anahtar kalıbı: eşleşme yok.
- Temizlik: smoke kendi projesini, volume'unu, `.local-smoke` dizinini ve 6 imajını sildi; Testcontainers konteynerleri kendiliğinden kaldırıldı; boşta derleme sunucuları kapatıldı. Komşu konteynerler sağlıklı.
- Kozmetik gözlem (düzeltilmedi): Pano çalışma alanında not tablosu başlığı 360 px genişlikte dar sütuna sıkışıyor.

| Komut | Exit | Toplam | Pass | Fail | Skip |
|---|---|---|---|---|---|
| `dotnet restore Halka.slnx --locked-mode` | 0 | — | — | — | — |
| `dotnet build Halka.slnx -c Release --no-restore -v q` (0 uyarı / 0 hata) | 0 | — | — | — | — |
| `npm run check` (`src/Halka.Iam/ui-tooling`) | 0 | 4 | 4 | 0 | 0 |
| Yayın kontrolü (`verify.ps1` adımları: 6 × `dotnet publish -c Release` + EF Core sürüm denetimi; dağıtım yok) | 0 | 6 uygulama | 6 | 0 | — |
| `./scripts/test.ps1 -Project E2E -Configuration Release -NoBuild -Filter '--filter-class','*<sınıf>'` × 4 | 0 | 3 + 3 + 4 + 3 | 13 | 0 | 0 |
| `./scripts/test.ps1 -Project E2E -Configuration Release -NoBuild` | 0 | 13 | 13 | 0 | 0 |
| `./scripts/smoke.ps1` (6 faz) | 0 | 16 | 16 | 0 | 0 |
| `./scripts/scan.ps1` (çevrimiçi) | 0 | 14 kontrol | 14 | 0 | 0 |
| `./scripts/source-fingerprint.ps1` (sonda) | 0 | aynı değer | — | — | — |

En düşük boş bellek: tarayıcı testleri 1,7 GB, smoke imaj derlemesi 0,4 GB. Uzak CI koşulmadı.

Sonraki adım: `docs/next-action.md` (bekleyen zorunlu iş yok).

## Aşama 10 sonrası — iki kozmetik düzeltme (2026-10-11, 14:25–14:38)

Kapsam: yalnız (1) dar ekranda sıkışan tablo başlığı, (2) `verify.ps1` log adının tr-TR'de bozulması. Yeni özellik yok.

- Başlangıç: git "No commits yet on main"; fingerprint `sha256:15015539afab3692006971ed65611ddfaefc93154ce5320822f69e1e007e12c9` (248 dosya); `halka*` konteyneri yok.
- **Kök neden (1):** 720 px altında `table.data` blok düzene geçiyor, `caption` ise `table-caption` kalıyordu; blok
  bir kapsayıcının içinde başlık en uzun kelimesinin genişliğine daralıyordu. Kural ortak olduğu için kusur yalnız
  Pano'da değil, Halka ID'nin dar ekrandaki bütün başlıklı tablolarında vardı. Düzeltme: `src/Halka.Iam/wwwroot/site.css`
  içinde aynı medya sorgusuna görünür başlık için `display: block`, hücrelerle aynı yatay boşluk ve alt çizgi.
- **Kök neden (2):** `-replace` büyük-küçük harf duyarsızdır ve geçerli kültürü izler; tr-TR'de `I`, `[a-zA-Z]`
  ile eşleşmiyordu. Düzeltme: `scripts/verify.ps1` içinde `Get-GateLogName` işlevi ve `-creplace`. Etkilenen ikinci
  ad da ortaya çıktı (`verify-u-tooling-…`).
- **Test değişikliği** (`tests/Halka.E2E/AccessibilityAndLayoutTests.cs`): her ekran ve genişlikte tablo başlığı
  genişliği kontrolü eklendi; Pano çalışma alanı kontrolünden önce not eklenir. Gerekçe: mevcut test kusuru
  yakalamıyordu ve Pano tablosunun görünmesi başka bir testin önce koşmuş olmasına bağlıydı. Var olan kontroller
  kaldırılmadı.
- Daha geniş doğrulama kararı: stil dosyası bütün ekranlarda ortak olduğu ve değişen test paylaşılan yığına not
  yazdığı için tam tarayıcı paketi (13) koşuldu. Backend / protokol kaynağı değişmediği için birim, tam
  entegrasyon, Compose smoke, yayın kontrolü ve `verify.ps1` paketi **koşulmadı**.
- Yeni fingerprint: `sha256:47adc621657715d0d0a98ecad97e0a86f416a65a208a90a8f4a56e13a135573d` (248 dosya). Önceki sonuçlar eski fingerprint içindir ve öyle kaldı.

| Komut | Exit | Toplam | Pass | Fail | Skip |
|---|---|---|---|---|---|
| Negatif kontrol: `./scripts/test.ps1 -Project E2E -Configuration Release -Filter '--filter-method','*A11y_KeyScreens_HaveNoAxeViolations_AndReflow_AtThreeWidths'` (CSS düzeltmesi yokken; beklenen hata) | 2 | 1 | 0 | 1 | 0 |
| `./scripts/test.ps1 -Project E2E -Configuration Release -Filter '--filter-class','*AccessibilityAndLayoutTests'` | 0 | 3 | 3 | 0 | 0 |
| `./scripts/test.ps1 -Project E2E -Configuration Release` | 0 | 13 | 13 | 0 | 0 |
| `dotnet build Halka.slnx -c Release --no-restore -v q` (0 uyarı / 0 hata) | 0 | — | — | — | — |
| `npm run check` (`src/Halka.Iam/ui-tooling`) | 0 | 4 | 4 | 0 | 0 |
| `./scripts/test.ps1 -Project Integration -Configuration Release -NoBuild -Filter '--filter-class','*UiRenderTests'` | 0 | 3 | 3 | 0 | 0 |
| aynı, `-Filter '--filter-method','*Health_OpenApi_AndSecurityHeaders_ArePresent'` | 0 | 1 | 1 | 0 | 0 |
| Log adları (`check-gate-log-names.ps1 -Culture tr-TR` / `en-US`, ayrı süreçler) | 0 / 0 | 9 + 9 ad | 18 | 0 | — |
| `Invoke-Gate` davranışı (`check-invoke-gate.ps1`, sahte kapılar) | 0 | 5 kontrol | 5 | 0 | — |
| `./scripts/scan.ps1` (çevrimiçi) | 0 | 14 kontrol | 14 | 0 | 0 |

Ekran görüntüleri (88) yeni fingerprint üzerinde yeniden üretildi; `pano-workspace` üç genişlikte gözle incelendi.
En düşük boş bellek 0,35 GB. Commit / push / dağıtım yok. Ayrıntı: `docs/final-verification.md` bölüm 6.
