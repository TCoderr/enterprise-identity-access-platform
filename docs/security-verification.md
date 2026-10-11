# Güvenlik Doğrulaması

Tehdit → kontrol → test → gerçek sonuç → kalan sınır. Test adları depodaki gerçek test metotlarıdır
(`tests/Halka.IntegrationTests`, `tests/Halka.E2E`, `tests/Halka.Smoke`, `tests/Halka.UnitTests`).

**"Sonuç" sütununun anlamı.** *Geçti* = testin son koşusu yeşil. Entegrasyon (**I**), birim (**U**), gerçek
tarayıcı (**E**) ve Compose smoke (**S**) testlerinin hepsi aynı kaynak durumunda (fingerprint
`sha256:15015539…`) koşulmuştur; komutlar, sayılar ve koşuların nasıl toplandığı `docs/final-verification.md`
içindedir. Sonraki iki kozmetik düzeltmeden (güncel fingerprint `sha256:47adc621…`; stil dosyası, bir tarayıcı
testi, `verify.ps1`) sonra yalnız **E** testleri (13 / 13) ve UI ile ilgili dört **I** testi yeniden koşulmuştur;
diğer **I**, **U** ve **S** sonuçları önceki fingerprint içindir.

Kapsam notu: bu belge otomatik testlerin ve yerel incelemenin kanıtıdır. Bağımsız sızma testi, OpenID Foundation
uyumluluk paketi ve yük testi **yapılmamıştır** (`docs/known-limitations.md`).

Kısaltmalar: **I** = entegrasyon (gerçek Kestrel HTTPS + Testcontainers PostgreSQL, kısıtlı runtime rolü),
**E** = gerçek tarayıcı (kurulu Chrome), **S** = Compose smoke, **U** = birim.

## 1. Tehdit modeli özeti

| Tehdit | Kontrol | Test | Sonuç | Kalan sınır |
|---|---|---|---|---|
| Kimlik bilgisi hırsızlığı / tahmin | PBKDF2 (Identity), genel hata mesajı, hesap kilidi, (adres, hesap) ve adres bazlı hız sınırı, MFA | I `Login_GenericError_IsIdenticalForUnknownWrongPasswordLockedOutAndDisabled`, `Login_PerAccountLimit_ThrottlesGuessing_WithoutRevealingAccounts_OrBlockingOthers`, `Login_PerAddressLimit_StopsSprayingAcrossAccounts_ForThatAddressOnly` | Geçti | Hız sınırı süreç belleğinde (tek instance); sızdırılmış parola listesi kontrolü yok |
| Kod yakalama / tekrar | PKCE S256 zorunlu, kod 2 dk ve tek kullanım, tekrar kullanımda ilk token'lar iptal | I `Code_WrongOrMissingVerifier_IsRejected`, `Code_WithoutS256Challenge_IsRejectedAtTheAuthorizationEndpoint`, `Code_SecondUse_IsRejected_AndTheTokensOfTheFirstUseAreRevoked`, `Code_Expired_IsRejected` | Geçti | — |
| Redirect kötüye kullanımı | Tam eşleşen kayıtlı URI; eşleşmezse istemciye yönlendirme yok; `returnUrl` yalnız yerel yol | I `Redirect_AnythingButTheExactRegisteredUri_IsRefusedWithoutRedirecting` (11 varyant), `ReturnUrl_NonLocalTarget_IsNotFollowed`, `EndSession_ForgedRedirect_IsRefused_AndLogoutNeedsAConfirmedPost`; E `OpenRedirect_AndCrossSiteConsentPost_AreRefusedInARealBrowser` | Geçti | — |
| Token karışıklığı (ID token'ı API'ye sunma, yanlış audience) | API yalnız introspection ile doğrulanmış access token kabul eder; audience kontrolü | I `Api_RejectsAnIdTokenPresentedAsBearer`, `Api_RejectsATokenThatWasNotIssuedForThisAudience`, `IdToken_IssuedForAnotherClient_IsRejected_WrongAudience` | Geçti | — |
| Refresh token tekrar kullanımı | Rotasyon, tolerans yok, atomik guard, aile + grant iptali | I `Refresh_ReuseOfARotatedToken_RevokesTheWholeFamilyAndTheGrant`, `Refresh_ParallelUseOfTheSameToken_RotatesExactlyOnce_AndTheFamilyEndsRevoked` | Geçti | Singleflight kullanmayan istemci yarışta oturumunu kaybeder (bilinçli) |
| MFA tekrar / atlatma | Timestep tek kabul (koşullu UPDATE), deneme sınırı, pending cookie kimlik değildir, admin için zorunlu | I `Totp_ParallelSameCode_IsAcceptedExactlyOnce`, `Login_WithMfa_PasswordAloneGivesNoSession_UntilAValidCode`, `Admin_WithoutMfa_CannotOpenTheAdministrationArea_AndCannotBypassIt` | Geçti | Yalnız TOTP; WebAuthn yok |
| CSRF / XSS | Tüm tarayıcı mutasyonlarında antiforgery; CSP (`default-src 'self'`, inline yok), Razor kodlaması | I `Csrf_LoginAndLogoutPostsWithoutToken_AreRejected`, `Consent_ForgedDecision_WithoutOrWithForeignAntiForgeryToken_GrantsNothing`, `Pano_MutationsRequireAnAntiForgeryToken`, `Health_OpenApi_AndSecurityHeaders_ArePresent`; E (konsol/CSP ihlali yok) | Geçti | Otomatik XSS taraması (DAST) yok |
| Oturum sabitleme | Her girişte yeni oturum kimliği, öncekini sonlandır | I `Login_RotatesSession_PreviousSessionOfTheBrowserIsEnded` | Geçti | — |
| Bayat rol | Roller her istekte DB'den | I `Admin_AreaRequiresAdministrativeRole_AndRoleRemovalAppliesImmediately`, `Admin_RoleChange_ThroughTheUi_NeedsPlatformAdmin_AndDemotionAppliesOnTheNextRequest` | Geçti | İstek başına DB maliyeti |
| Özel anahtar sızıntısı | Anahtarlar DB'de Data Protection ile sarılı; `.local/` git ve imaj dışı; JWKS yalnız public | I `Jwks_PublishesOnlyPublicSigningKeyMaterial`; S `Images_ContainNoSecretOrPrivateKeyMaterial` (+ pozitif kontrol), `Logs_ContainNoSecretValues`; `scripts/scan.ps1` | Geçti | HSM/KMS yok |
| Admin ele geçirme | MFA zorunlu, hassas işlemde taze step-up, son PlatformAdmin koruması | I `Admin_SensitiveActions_NeedARecentStepUp_AStolenAdminCookieAloneChangesNothing`, `LastAdmin_ConcurrentDemotionAndDisable_AlwaysLeavesOneActivePlatformAdmin`; E `Admin_EnrollsMfa_SignsInWithCodeAndRecoveryCode_AndStepsUpForASensitiveAction` | Geçti | Yönetici onay akışı (dört göz) yok |
| Sağlayıcı / DB kesintisi | Fail-closed: 503, cookie korunur, başarıya düşüş yok | I `Outage_IdentityProviderDown_ApiAndBffFailClosed_ThenRecoverWithTheSameTokensAndKeys`, `DatabaseDown_EverySurfaceFailsClosedWithAStandard503_ThenRecoversWithTheSameSessionsAndTokens`; S `db-down`, `db-recovered`, `op-down`, `op-recovered` fazları | Geçti | Tek instance; yüksek erişilebilirlik yok |

## 2. Kabul sözleşmesi eşlemesi

### 4.1 Authorization code / OIDC

| Madde | Test | Sonuç |
|---|---|---|
| Code + PKCE S256, exact redirect, state/nonce istemci kütüphanesinde | I `Code_WithPkce_IssuesOpaqueAccessTokenAndSignedIdToken`, `Pano_SignInThroughTheIdentityProvider_ThenCallsTheApi`, `Pano_Callback_WithoutState_WithForeignState_OrReplayed_IsRejectedByTheClient`, `IdToken_FromAnotherAuthorizationRequest_IsRejected_NonceMismatch` | Geçti |
| Yanlış verifier / client / redirect, süresi dolmuş / tekrar kod | I `Code_WrongOrMissingVerifier_IsRejected`, `Code_RedeemedByAnotherClient_OrWithWrongSecretOrRedirectUri_IsRejected`, `Code_Expired_IsRejected`, `Code_SecondUse_IsRejected_AndTheTokensOfTheFirstUseAreRevoked` | Geçti |
| Response type / grant / scope sınırları | I `Client_ImplicitAndHybridResponseTypes_AreRefused`, `Token_PasswordGrantAndUnknownClient_AreRefusedWithStandardOAuthErrors`, `Client_CannotObtainAScopeItIsNotAllowed` | Geçti |
| Consent: gerçek client adı / scope, anti-CSRF | I `Consent_ForgedDecision_WithoutOrWithForeignAntiForgeryToken_GrantsNothing`, `Consent_Denied_ReturnsAccessDenied_AndCreatesNoGrant`, `Consent_IsRemembered_AskedAgainForNewScopes_AndForPromptConsent`; E `Consent_Denied_InARealBrowser_ReturnsToTheApplicationWithoutASession` | Geçti |
| `prompt=none` | I `Prompt_None_ReturnsLoginRequired_ConsentRequired_OrACode` | Geçti |
| `prompt=login`, `max_age`, `auth_time` | I `Prompt_Login_CannotBeSatisfiedByAnExistingSsoCookie`, `MaxAge_OlderSession_MustAuthenticateAgain_AndAuthTimeIsReported`, `Bff_SignInAgainFresh_ForcesCredentialsAtTheProvider_AndReportsANewAuthenticationTime`; E `Mfa_SignInAtPano_ThenSensitiveApi_ThenRaporSso_AndAFreshSignInAsksForBothFactorsAgain` | Geçti |
| ID token API'de kabul edilmez | I `Api_RejectsAnIdTokenPresentedAsBearer` | Geçti |
| Issuer / audience / alg allowlist; `alg=none`, bozulmuş, süresi dolmuş | I `IdToken_WithModifiedSignature_IsRejected`, `IdToken_WithModifiedPayload_IsRejected`, `IdToken_WithAlgNone_IsRejected`, `IdToken_SignedByAnotherKey_WithTheSameKeyId_OrAnotherIssuer_IsRejected`, `IdToken_Expired_IsRejectedByTheClient`, `Api_WithoutToken_OrWithGarbageOrTamperedToken_Returns401WithBearerChallenge` | Geçti |
| UserInfo / claim minimizasyonu | I `UserInfo_AndIdToken_OnlyContainClaimsOfGrantedScopes` | Geçti |
| Discovery / JWKS yalnız public | I `Discovery_AdvertisesExactlyTheSupportedProtocolSurface`, `Jwks_PublishesOnlyPublicSigningKeyMaterial` | Geçti |

Sınır: Geçerli imzalı fakat yanlış issuer taşıyan ID token sağlayıcının anahtarı olmadan üretilemez; issuer kontrolü
saldırgan anahtarıyla yeniden imzalanmış token ve discovery issuer eşitliği üzerinden sınandı.

### 4.2 MFA ve step-up

| Madde | Test | Sonuç |
|---|---|---|
| Enrollment: taze parola, geçerli kod olmadan etkin değil, secret at-rest korumalı, tek gösterim | I `Enrollment_IsOnlyActivatedByAValidCode_AndTheSecretIsProtectedAtRest`, `Enrollment_NeedsARecentPassword_ForAccountsWithoutMfa`; E `Admin_EnrollsMfa_...` (QR gerçek görüntü, yeniden yüklemede secret/kod yok) | Geçti |
| QR yerelde üretilir | E dış istek kaydı boş (`session.Problems`), QR `img` yerel `data:` kaynağı | Geçti |
| Saat kayması sınırı, deneme sınırı, challenge süresi | I `Totp_ClockSkewOfOneStepIsAccepted_TwoStepsIsNot`, `Challenge_AttemptLimit_ForcesTheUserBackToThePassword`, `Challenge_Expired_CannotBeCompleted` | Geçti |
| Aynı TOTP adımı eşzamanlı tek kabul | I `Totp_ParallelSameCode_IsAcceptedExactlyOnce`, `Totp_SameCode_CannotBeUsedTwice_AndOlderStepsAreRefusedAfterANewerOne` | Geçti |
| Recovery: tek kullanım, paralel tek başarı, yenilemede eskiler iptal, hash'li | I `Recovery_CodeSignsInOnce_ParallelUseSucceedsOnce_AndIsReportedWithoutOtp`, `Recovery_Regenerate_InvalidatesEveryOldCode` | Geçti |
| Devre dışı / yeniden kayıt / kod yenileme taze ikinci faktör ister | I `DisableAndRegenerate_NeedARecentSecondFactor_AStaleSessionIsNotEnough` | Geçti |
| Pending cookie kimlik yerine geçmez | I `Login_WithMfa_PasswordAloneGivesNoSession_UntilAValidCode`; E (MFA sayfasında hiçbir oturum cookie'si yok) | Geçti |
| Admin MFA'yı atlayamaz | I `Admin_WithoutMfa_CannotOpenTheAdministrationArea_AndCannotBypassIt`, `Admin_WithMfa_NeedsTheSecondFactorAtEverySignIn`, `StepUp_PasswordIsNotAcceptedForAccountsWithMfa_AndReturnUrlMustBeLocal` | Geçti |
| `amr` / `auth_time` gerçeği yansıtır; API "MFA gerekli" politikası | I `Api_SensitiveEndpoint_RequiresMultiFactorSignIn_PasswordOnlySessionIsRefused`, `Recovery_..._IsReportedWithoutOtp` | Geçti |
| Parola sıfırlama / değişimi, hesap devre dışı: oturum / grant politikası | I `Reset_ChangesThePassword_EndsEverySessionAndGrant_AndDoesNotSignAnyoneIn`, `Reset_KeepsTheSecondFactor_SoAStolenMailboxAloneCannotSignIn`, `Account_ChangePassword_KeepsThisSession_EndsOthers_AndTheOldPasswordStopsWorking`, `Revoke_UserDisabled_EndsSessionsAndTokensAtOnce_AndBlocksEveryWayBackIn` | Geçti |

MFA sıfırlama: yalnız SecurityAdmin / PlatformAdmin, MFA + taze step-up ile ve denetim kaydıyla yapabilir
(`UserAdminService.ResetMfaAsync`); sessiz bir destek uç noktası yoktur. Data Protection anahtarları kaybolursa
TOTP secret'ları ve protokol anahtarları çözülemez (yeniden kayıt / yeni anahtar gerekir).

### 4.3 Refresh / token / iptal

| Madde | Test | Sonuç |
|---|---|---|
| Rotasyon, tekrar kullanım tespiti, aile iptali | I `Refresh_Rotates_TheOldRefreshTokenIsDead_AndAccessTokensKeepWorking`, `Refresh_ReuseOfARotatedToken_RevokesTheWholeFamilyAndTheGrant` | Geçti |
| Paralel refresh: tam bir başarı; istemci singleflight | I `Refresh_ParallelUseOfTheSameToken_RotatesExactlyOnce_AndTheFamilyEndsRevoked` (10 tur), `Bff_ConcurrentRequests_RefreshOnce_SingleFlight_AndNeverLookLikeTokenReuse` | Geçti |
| Token ↔ oturum ↔ grant bağı DB otoritesi | I `Tokens_DoNotOutliveTheCentralSession_RefreshCountsAsActivity`, `Refresh_CannotBeUsedByAnotherClient_OrToWidenScopes` | Geçti |
| Anında API erişim iptali (reference token + introspection, önbellek yok) | I `Revoke_Grant_DeniesTheApiImmediately_OtherClientAndSessionUnaffected`, `Consent_Revoked_KillsTheClientsTokensImmediately_AndConsentIsAskedAgain` | Geçti |
| Kesintide fail-closed, "geçersiz" ile "doğrulanamadı" ayrımı | I `Outage_IdentityProviderDown_ApiAndBffFailClosed_...`, `DatabaseDown_EverySurfaceFailsClosedWithAStandard503_...` | Geçti |
| Revocation uç noktası: sahiplik, bilgi sızdırmama | I `Revocation_Endpoint_RevokesOwnTokens_AndGivesNothingAwayAboutOthers`, `Introspection_IsOnlyAnsweredForTheAudienceOrThePresenter_AndRequiresClientAuthentication` | Geçti |
| Etki matrisi (client / kullanıcı / consent) | `docs/revocation-matrix.md` | Geçti |
| Yeniden başlatmada token deposu kalıcı | I `Outage_..._ThenRecoverWithTheSameTokensAndKeys`; S `ApplicationSession_Tokens_AndSigningKeys_SurviveARestart` | Geçti |
| Yakalanmış cookie tekrar oynatma | I `Session_CapturedCookieAfterLogout_IsDenied`, `GlobalLogout_EndsEveryApplicationSession_CapturedCookiesOfBothAppsAndTheProviderAreDenied`; E `SessionCookie_CopiedIntoAnotherBrowser_StopsWorkingAfterLogout`, `Revocation_AtTheProvider_IsSeenByBothApplications_AndByCopiedCookies` | Geçti |
| Token / sır log'da yok | I `Tokens_AreNeverWrittenToLogsOrAudit`, `Logs_AndAudit_ContainNoCredentialTokenOrPersonalData`; S `Logs_ContainNoSecretValues` | Geçti |

### 4.4 SSO ve logout

| Madde | Test | Sonuç |
|---|---|---|
| A'da giriş (+MFA) → B'de kimlik bilgisiz SSO; B'nin consent'i yine istenir | I `Sso_SignedInToPano_ThenRapor_NeedsNoCredentials_ButStillAsksForRaporsConsent`; E `Pano_Login_ThenApi_ThenRapor_SingleSignOn_InARealBrowser`, `Mfa_SignInAtPano_...`; S `Sso_AcrossContainers_PanoThenRaporWithoutASecondSignIn_AndTheApiAcceptsTheirTokens` | Geçti |
| RP oturumu ≠ OP oturumu; yerel çıkış yalnız o uygulamayı kapatır | I `Bff_LocalLogout_RevokesItsOwnTokensAtTheProvider_AndKeepsTheCentralSession` | Geçti |
| RP-initiated end session: kayıtlı URI, sahte yönlendirme reddi, onaylı POST | I `EndSession_ForgedRedirect_IsRefused_AndLogoutNeedsAConfirmedPost` | Geçti |
| Merkezi iptal sonrası A / B eski cookie ile kaynak alamaz (server-state kontrolü) | I `GlobalLogout_...`, `Bff_GrantRevokedAtTheProvider_EndsTheApplicationSessionOnTheNextRequest`; E `Revocation_AtTheProvider_...` | Geçti |
| Çıkışta önbellek temizliği, `no-store` | I `Bff_LocalLogout_...` (`Clear-Site-Data`); E `NormalUser_CannotReachAdministration_AndLoggedOutPagesAreNotServedFromCache` | Geçti |
| Cookie'ler: Secure, HttpOnly, host-only, Lax; correlation / nonce yaşam döngüsü | E `Pano_Login_ThenApi_ThenRapor_...`; S `Stack_IsReady_OverHttpsWithTheLocalCa_AndCookiesAreSecure` | Geçti |

Back-channel logout uygulanmadı; yerine istek başına server-state kontrolü seçildi (ADR-0006).

### 4.5 İstemci kimlik bilgisi ve anahtar rotasyonu

| Madde | Test | Sonuç |
|---|---|---|
| Secret CSPRNG, tek gösterim, yalnız hash | I `ClientSecret_Create_IsReturnedOnce_AndOnlyItsHashIsStored`, `Admin_ClientRegistration_ShowsTheSecretOnce_AndRotationWorksThroughTheUi`, `ClientSecrets_AreStoredHashed_AndNeverExposedByPublicEndpoints`; E `Admin_DisablesAndEnablesAClient_RegistersAMachineClient_AndRotatesItsSecret_InTheBrowser` | Geçti |
| Grace penceresi; sonunda eski secret reddi | I `ClientSecret_Rotation_OldSecretWorksOnlyDuringTheGraceWindow`, `ClientSecret_RotationWithoutGrace_StopsTheOldSecretAtOnce_IncludingEarlierGraceEntries` | Geçti |
| Yeni anahtar etkinleşmesi, overlap, erken emeklilik reddi | I `Keys_SigningRotation_NewTokensUseTheNewKey_OldTokensStayValid_ClientsFollow_AndStateSurvivesARestart`, `Keys_Retire_IsOnlyPossibleAfterTheOverlap_AndThenRemovesTheKey`, `Keys_EncryptionRotation_KeepsExistingReferenceTokensReadable`, `Keys_AtMostOneActiveKeyPerUse_IsEnforcedByTheDatabase_EvenForConcurrentRotations` | Geçti |
| Acil rotasyon ayrı davranış | I `Keys_EmergencyRevoke_RemovesTheKeyImmediately_RevokesAllGrants_AndKeepsCentralSessions` | Geçti |
| Özel anahtar kaynak / imajda yok; non-root | S `Images_ContainNoSecretOrPrivateKeyMaterial`, `Scanner_PositiveControl_FindsEveryPlantedLeak`, `Containers_RunAsNonRoot_WithReadOnlyRootAndNoCapabilities`; `scripts/scan.ps1` | Geçti |
| TLS ≠ imza ≠ şifreleme ≠ Data Protection anahtarı | Tasarım: `.local/tls`, `protocol_keys` (kullanım başına ayrı satır), `.local/dp-keys` + ayrı sarma sertifikası (ADR-0008, ADR-0009) | İnceleme |
| JWKS önbelleği / bayat istemci | I `Keys_SigningRotation_..._ClientsFollow_...` | Geçti |

### 4.6 Kimlik / yönetim / operasyon

| Madde | Test | Sonuç |
|---|---|---|
| Rol DB otoritesi; rol kaldırma eski cookie ile aşılamaz | I `Admin_AreaRequiresAdministrativeRole_AndRoleRemovalAppliesImmediately`, `Admin_RoleSeparation_EachRoleOnlyReachesItsOwnPages` | Geçti |
| Mass assignment / IDOR | I `Signup_ConfirmationThroughPrivateSink_ThenLoginWorks_AndOnlyUserRoleIsGranted`, `Idor_AnotherUsersSession_CannotBeRevokedThroughPageOrApi`, `Admin_SessionAndGrantRevocation_IsBoundToTheAccountInTheRoute`; E `AnotherUsersSession_CannotBeEndedFromTheBrowser_ThroughTheApiOrATamperedForm` | Geçti |
| Son PlatformAdmin yarışı | I `LastAdmin_ConcurrentDemotionAndDisable_AlwaysLeavesOneActivePlatformAdmin` | Geçti |
| Hız sınırı boyutları (hesap, adres, client) | I `RateLimitTests` (6 test): giriş hesap / adres, kurtarma, kayıt, token (client başına), ikinci faktör | Geçti |
| Enumeration yok; mail sink'e yetkisiz erişim yok | I `Signup_ExistingAddress_GetsTheSameResponse_AndNoSecondAccountOrMail`, `Reset_Request_AnswersTheSameForEveryAddress_AndOnlyEligibleAccountsGetMail`, `MailSink_IsNotReachableOverHttp_AndTokensAreStoredOnlyAsHashes` | Geçti |
| Parola sıfırlama token'ı: tek kullanım, süre, eşzamanlılık | I `Reset_Link_IsSingleUse_AndAReplayChangesNothing`, `Reset_ConcurrentUseOfOneLink_ExactlyOneRequestWins`, `Reset_Link_WorksUntilItsLifetimeEnds_AndNotAfter`, `Reset_NewRequest_InvalidatesTheOlderLink`, `Reset_WeakPassword_IsRejected_AndTheLinkCanStillBeUsed`, `Reset_AccountDisabledAfterTheRequest_CannotCompleteIt`, `Confirmation_Link_ExpiresAfterItsLifetime` | Geçti |
| ProblemDetails (ürün API) ↔ OAuth hataları (protokol) | I `Api_InsufficientScope_Returns403WithStandardChallengeAndProblemDetails`, `Token_PasswordGrantAndUnknownClient_AreRefusedWithStandardOAuthErrors`, `DatabaseDown_...` (protokol: OAuth nesnesi, `/api`: problem+json, sayfa: statik HTML) | Geçti |
| DB rolleri; audit salt-ekleme | I `DbRoles_RuntimeRole_CannotChangeTheSchema`, `DbRoles_AuditTable_IsAppendOnlyForTheRuntimeRole`, `DbRoles_RuntimeRole_HasNoElevatedAttributes` | Geçti |
| Audit / log'da parola, token, TOTP secret, kurtarma kodu, e-posta, IP yok | I `Logs_AndAudit_ContainNoCredentialTokenOrPersonalData` (18+ değer türü), `MailSink_...` | Geçti |
| Metrikler düşük kardinalite | I `Metrics_CountSecurityEvents_WithFixedLowCardinalityTagsOnly` | Geçti |
| Outbox: aynı transaction, lease, fencing, retry, DLQ, kurtarma, idempotent sink | I `Lease_ParallelWorkers_GetEveryMessageExactlyOnce`, `Lease_OfACrashedWorker_IsTakenOverAfterItExpires_AndTheOldWorkerIsFencedOut`, `Delivery_ThatKeepsFailing_BacksOffExponentially_ThenIsDeadLettered`, `Delivery_RecoversWhenTheSinkComesBack_AndDeliversOnce`, `Worker_DeliversQueuedMail_PicksUpNewMailOnTheNextTick_AndStopsCleanly` | Geçti |
| Saklama (retention) yalnız ölü kayıtları siler | I `Retention_RemovesOnlyDeadRecords_InStages_AndNeverTheAuditLogOrLiveState` | Geçti |
| Readiness / liveness, zarif kapanış | I `Health_OpenApi_AndSecurityHeaders_ArePresent`, `DatabaseDown_...`; S `DatabaseOutage_FailsClosed_LivenessStaysUpReadinessGoesDown` | Geçti |

## 3. Test ortamı güvenliği

| Kural | Kanıt |
|---|---|
| Yalnız atılabilir, sahipliği işaretli veritabanına yazma (açık izin + işaret satırı + sunucu kimliği / port) | I `TestGuard_WrongTarget_IsRefusedAndNothingIsWritten` |
| Migration: model uyumu, boş uygulama, önceki aşamadan yükseltme, idempotent script | I `Migration_ModelHasNoPendingChanges_AndReapplyingIsANoOp`, `Upgrade_FromTheStage1AndStage3Schemas_KeepsExistingData_AndTheResultIsUsable`, `IdempotentScript_AppliedTwice_ProducesTheSameSchemaAsTheMigrator` |
| Eşzamanlılık kanıtı uyku ile değil değişmezlerle | Paralel testler `Task.WhenAll` + "tam bir başarı" değişmezi; saat `FakeTimeProvider`; `Eventually.TrueAsync` yalnız arka plan worker etkisini son tarihle beklemek için |
| Tarayıcı sertifika doğrulaması kapatılmaz | Chrome yalnız bu koşunun sertifika SPKI özetlerini kabul eder (`--ignore-certificate-errors-spki-list`) |
| Tarayıcı: gerçek kurulu Chrome, dört ayrı HTTPS origin | `tests/Halka.E2E/BrowserFixture.cs` |
| Taramanın pozitif kontrolü | `scripts/scan.ps1` (ekilmiş örnek), S `Scanner_PositiveControl_FindsEveryPlantedLeak` |

## 4. Otomatik olmayan doğrulama

- **Görsel inceleme:** 360 / 768 / 1440 px ekran görüntüleri (`artifacts/verification/screenshots`) üretildi ve
  giriş, consent, MFA kaydı, yönetim detay, anahtarlar ve workspace ekranları gözle incelendi; bulunan taşma ve
  boşluk sorunları düzeltildi (`docs/implementation-progress.md`, Aşama 8).
- **Erişilebilirlik:** axe-core otomatik kuralları (0 ihlal) ve klavye ile giriş senaryosu otomatik. Ekran okuyucu
  ile elle test **yapılmadı**.
