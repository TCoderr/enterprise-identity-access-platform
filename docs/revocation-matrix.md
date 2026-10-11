# İptal (Revocation) Matrisi

Hangi eylem neyi, ne kadar sürede geçersiz kılar ve hangi testle kanıtlıdır.

## Model

```
Merkezi oturum (user_sessions) ──1:N──▶ Grant (session_grants ↔ OpenIddict authorization) ──1:N──▶ Token (code / access / refresh)
Consent (consents): kullanıcı × client, oturumdan bağımsız
Uygulama oturumu (Pano / Rapor app_sessions): RP tarafında, kendi cookie'si ve kendi token'ları ile
Makine token'ı: grant'siz, yalnız client'a bağlı
```

- Access ve refresh token'lar **reference token**'dır; kaynak API her istekte introspection yapar, sonucu
  **önbelleğe almaz**. Introspection ve token uç noktası her seferinde grant, oturum, kullanıcı ve client durumunu
  veritabanından okur.
- Pano / Rapor (BFF) korumalı her istekte kendi token'ının hâlâ geçerli olduğunu sağlayıcıda doğrular; geçersizse
  uygulama oturumunu siler. Back-channel logout yoktur (ADR-0006).
- "Gecikme" sütunu: **Anında** = iptal işlemi commit edildikten sonraki ilk istekte ret (aynı veritabanı; önbellek
  yok). ID token'lar 5 dakikalık kendi içinde doğrulanan JWT'lerdir ve iptal edilemez; yalnız oturum açma anındaki
  kimlik kanıtıdır, API'de kabul edilmez.

## Matris

Sütunlar: **OP** merkezi oturum · **A** Pano uygulama oturumu · **B** Rapor uygulama oturumu · **AT** access
token (API erişimi) · **RT** refresh token · **Grant** · **Makine** makine istemcisi token'ları.
✖ = geçersiz olur, — = etkilenmez.

| Eylem | OP | A | B | AT | RT | Grant | Makine | Gecikme | Sonraki giriş | Kanıt |
|---|---|---|---|---|---|---|---|---|---|---|
| Pano'da yerel çıkış ("Sign out of Pano only") | — | ✖ | — | ✖ (yalnız Pano'nun) | ✖ (yalnız Pano'nun) | — (kayıt kalır, kullanılabilir token'ı kalmaz) | — | Anında | Pano: parolasız SSO, yeni grant | I `Bff_LocalLogout_RevokesItsOwnTokensAtTheProvider_AndKeepsTheCentralSession` |
| Global çıkış (RP-initiated end session veya `/account/logout`) | ✖ (o oturum) | ✖ | ✖ | ✖ | ✖ | ✖ (o oturumun tümü) | — | Anında (A/B: sonraki istekte) | Parola (+MFA) gerekir | I `GlobalLogout_EndsEveryApplicationSession_CapturedCookiesOfBothAppsAndTheProviderAreDenied`; E `SessionCookie_CopiedIntoAnotherBrowser_StopsWorkingAfterLogout` |
| Kullanıcı: tek oturumu sonlandır (`/manage/sessions`) | ✖ (seçilen) | ✖ (o oturumdan açılanlar) | ✖ (aynı) | ✖ | ✖ | ✖ (o oturumun) | — | Anında | Diğer oturumlar sürer | I `Session_UserCanRevokeOwnOtherSession_AndSignOutEverywhere` |
| Kullanıcı: her yerden çıkış ("Sign out everywhere") | ✖ (tümü) | ✖ | ✖ | ✖ | ✖ | ✖ (kullanıcının tümü) | — | Anında | Parola (+MFA) | E `Revocation_AtTheProvider_IsSeenByBothApplications_AndByCopiedCookies` |
| Kullanıcı: uygulama iznini geri çek (`/manage/apps`) | — | ✖ (o client) | — | ✖ (o client) | ✖ (o client) | ✖ (kullanıcı × client, tüm oturumlar) + consent ✖ | — | Anında | SSO var, consent yeniden sorulur | I `Consent_Revoked_KillsTheClientsTokensImmediately_AndConsentIsAskedAgain`, `Account_ConnectedApps_AndActivity_ShowOnlyOwnData_AndWithdrawingAccessKillsTokens`; E `Revocation_AtTheProvider_...` |
| Admin: grant iptali | — | ✖ (o client) | — | ✖ | ✖ | ✖ (seçilen) | — | Anında | SSO ile yeni grant alınabilir (consent durur) | I `Revoke_Grant_DeniesTheApiImmediately_OtherClientAndSessionUnaffected`, `Bff_GrantRevokedAtTheProvider_EndsTheApplicationSessionOnTheNextRequest`, `Admin_SessionAndGrantRevocation_IsBoundToTheAccountInTheRoute` |
| Admin: oturum sonlandırma | ✖ (seçilen) | ✖ | ✖ | ✖ | ✖ | ✖ (o oturumun) | — | Anında | Parola (+MFA) | I `Admin_SessionAndGrantRevocation_IsBoundToTheAccountInTheRoute` |
| Kullanıcı devre dışı | ✖ (tümü) | ✖ | ✖ | ✖ | ✖ | ✖ (tümü) | — | Anında | Giriş, sıfırlama ve SSO reddedilir | I `Revoke_UserDisabled_EndsSessionsAndTokensAtOnce_AndBlocksEveryWayBackIn`, `Session_DisabledUser_IsDeniedOnNextRequestAndCannotSignInAgain` |
| Parola sıfırlama (e-posta bağlantısı) | ✖ (tümü) | ✖ | ✖ | ✖ | ✖ | ✖ (tümü) | — | Anında | Yeni parola (+MFA; ikinci faktör korunur) | I `Reset_ChangesThePassword_EndsEverySessionAndGrant_AndDoesNotSignAnyoneIn`, `Reset_KeepsTheSecondFactor_SoAStolenMailboxAloneCannotSignIn` |
| Parola değiştirme (oturum içinden) | ✖ (bu oturum hariç tümü) | ✖ (diğer oturumlardan) | ✖ (aynı) | ✖ (diğer oturumların) | ✖ (aynı) | ✖ (diğer oturumların) | — | Anında | Bu oturum sürer | I `Account_ChangePassword_KeepsThisSession_EndsOthers_AndTheOldPasswordStopsWorking` |
| Zorunlu yeniden giriş (`prompt=login` / `max_age`) | ✖ (eski oturum; yenisi açılır) | ✖ (eski oturumdan) | ✖ (eski oturumdan) | ✖ | ✖ | ✖ (eski oturumun) | — | Anında | İsteyen uygulama yeni oturumla döner; diğerleri SSO ile | I `Prompt_Login_CannotBeSatisfiedByAnExistingSsoCookie`, `Login_RotatesSession_PreviousSessionOfTheBrowserIsEnded` |
| Rol kaldırma | — | — | — | — | — | — | — | Anında (sonraki istek) | Yönetim sayfaları 403 | I `Admin_AreaRequiresAdministrativeRole_AndRoleRemovalAppliesImmediately` |
| Client devre dışı | — | ✖ (o client) | — (başka client) | ✖ (o client) | ✖ | ✖ (client'ın tümü) | ✖ (client makine ise) | Anında | Authorize, token, introspection ve revoke o client için reddedilir | I `Revoke_ClientDisabled_KillsItsTokensAndBlocksAllOfItsEndpoints_OtherClientsContinue`, `Machine_Disabled_TokenRequestsFail_AndIssuedTokensStopWorking`; E `Admin_DisablesAndEnablesAClient_...` |
| Client secret rotasyonu (grace ile) | — | — | — | — | — | — | — | Eski secret grace sonunda reddedilir | Mevcut token'lar etkilenmez | I `ClientSecret_Rotation_OldSecretWorksOnlyDuringTheGraceWindow` |
| Client secret rotasyonu (grace yok; sızıntı şüphesi) | — | — | — | — | — | — | — | Eski secret anında reddedilir | Sızıntıda ayrıca "client devre dışı" veya grant iptali uygulanır | I `ClientSecret_RotationWithoutGrace_StopsTheOldSecretAtOnce_IncludingEarlierGraceEntries`; E `Admin_DisablesAndEnablesAClient_...` |
| Refresh token tekrar kullanımı (otomatik) | — | ✖ (o client) | — | ✖ (aile) | ✖ (aile) | ✖ (o grant) | — | Anında | SSO ile yeni grant | I `Refresh_ReuseOfARotatedToken_RevokesTheWholeFamilyAndTheGrant`, `Refresh_ParallelUseOfTheSameToken_RotatesExactlyOnce_AndTheFamilyEndsRevoked` |
| Yetkilendirme kodu tekrar kullanımı (otomatik) | — | — | — | ✖ (o koddan üretilenler) | ✖ | — | — | Anında | — | I `Code_SecondUse_IsRejected_AndTheTokensOfTheFirstUseAreRevoked` |
| Revocation uç noktası (client kendi token'ını iptal eder) | — | — | — | ✖ (verilen token) | ✖ (verilen token) | — | ✖ (verilen token) | Anında | — | I `Revocation_Endpoint_RevokesOwnTokens_AndGivesNothingAwayAboutOthers` |
| Merkezi oturum zaman aşımı (boşta 60 dk / mutlak 12 sa) | ✖ | ✖ | ✖ | ✖ | ✖ | ✖ (kullanılamaz; saklama işi kapatır) | — | Süre dolduğu anda | Parola (+MFA) | I `Session_IdleTimeout_EndsTheSessionAndRecordsTheReason`, `Session_AbsoluteLifetime_CannotBeExtendedByActivity`, `Tokens_DoNotOutliveTheCentralSession_RefreshCountsAsActivity`, `Retention_RemovesOnlyDeadRecords_...` |
| İmza anahtarı rotasyonu (planlı) | — | — | — | — | — | — | — | Yeni token'lar yeni `kid`; eski anahtar overlap boyunca doğrular | Kesinti yok | I `Keys_SigningRotation_NewTokensUseTheNewKey_OldTokensStayValid_ClientsFollow_AndStateSurvivesARestart` |
| Anahtar acil iptali (sızıntı) | — | ✖ | ✖ | ✖ (tümü) | ✖ (tümü) | ✖ (tümü) | ✖ (tümü) | Anında | Merkezi oturum sürer; uygulamalar SSO ile yeni token alır | I `Keys_EmergencyRevoke_RemovesTheKeyImmediately_RevokesAllGrants_AndKeepsCentralSessions` |
| Tarayıcıda cookie silme | — | — | — | — | — | — | — | — | **İptal değildir**: sunucudaki oturum sürer; kopyalanmış cookie çalışmaya devam eder | Karşı kanıt: iptalden sonra kopya cookie reddi (yukarıdaki E testleri) |

## Kesinti durumları (iptal değil, doğrulanamama)

| Durum | Davranış | Kanıt |
|---|---|---|
| Sağlayıcı ulaşılamıyor | API: 503 + `Retry-After`, `WWW-Authenticate` yok (token "geçersiz" denmez). BFF: 503, korumalı içerik yok, cookie korunur. Geri gelince aynı oturum ve token'larla devam | I `Outage_IdentityProviderDown_ApiAndBffFailClosed_ThenRecoverWithTheSameTokensAndKeys`; S `op-down`, `op-recovered` |
| Sağlayıcının veritabanı ulaşılamıyor | Sayfalar: statik 503. Protokol uç noktaları: 503 + OAuth hata nesnesi (`temporarily_unavailable`). `/api`: 503 problem+json. Refresh token tüketilmez, tekrar kullanım sayılmaz | I `DatabaseDown_EverySurfaceFailsClosedWithAStandard503_ThenRecoversWithTheSameSessionsAndTokens`; S `db-down`, `db-recovered` |

## Sınırlar

- ID token iptal edilemez (5 dk ömür); yetkilendirme için kullanılmaz.
- İptal gecikmesi "anında" iddiası tek veritabanı ve önbelleksiz introspection içindir. Kaynak API'ye introspection
  önbelleği eklenirse gecikme önbellek süresi kadar olur (eklenmedi).
- Pano / Rapor oturumu, iptalden sonra tarayıcı bir istek yapana kadar tarayıcıda "açık" görünür (sunucu itmez);
  korumalı içerik ilk istekte reddedilir.
- Çok instance / dağıtık önbellek senaryosu doğrulanmadı.
