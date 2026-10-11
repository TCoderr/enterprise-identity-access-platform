# 04 — Veritabanı Tasarımı

PostgreSQL 17. Üç veritabanı: `halka_iam`, `halka_pano`, `halka_rapor`. İsimlendirme snake_case (`EFCore.NamingConventions`). Tüm zamanlar UTC `timestamptz`; uygulama zamanı `TimeProvider`'dan gelir.

## 1. Roller

| Rol | Veritabanı | Yetki |
|---|---|---|
| `halka_migrator` | hepsi (owner) | DDL, seed. Yalnız `migrator` container'ı kullanır |
| `halka_iam_app` | `halka_iam` | `SELECT/INSERT/UPDATE/DELETE` (tablolar), sequence kullanımı; **DDL yok** |
| `halka_pano_app`, `halka_rapor_app` | kendi DB'si | `app_sessions` üzerinde DML |

Audit kısıtı: `halka_iam_app` için `audit_events` tablosunda yalnız `INSERT, SELECT`; `UPDATE/DELETE/TRUNCATE` açıkça `REVOKE` edilir. Grant'ler her migration çalıştırmasında Migrator tarafından idempotent uygulanır ve entegrasyon testleriyle doğrulanır.

## 2. `halka_iam` tabloları

### 2.1 Identity (ASP.NET Core Identity, `Guid` anahtar)
`users` (ek kolonlar: `display_name`, `is_disabled`, `disabled_at`, `created_at`), `roles`, `user_roles`, `user_claims`, `role_claims`, `user_logins`, `user_tokens`.
Parola: Identity `PasswordHasher` (PBKDF2). Lockout: 5 hata → 5 dk.

### 2.2 OpenIddict (`Guid` anahtar)
`"OpenIddictApplications"`, `"OpenIddictAuthorizations"`, `"OpenIddictScopes"`, `"OpenIddictTokens"` (kütüphanenin kendi tablo adları; kolonlar snake_case). Şema kütüphaneye aittir; iş kuralları için aşağıdaki tablolar ilişkilendirilir.

### 2.3 Ürün tabloları

| Tablo | Anahtar kolonlar | Kural |
|---|---|---|
| `user_sessions` | `id`, `user_id`, `created_at`, `auth_time`, `amr`, `password_verified_at`, `mfa_verified_at`, `last_seen_at`, `absolute_expires_at`, `revoked_at`, `revoked_reason`, `client_label` | Aktif = `revoked_at IS NULL` ∧ süre dolmamış. Index `(user_id, revoked_at)` |
| `session_grants` | `authorization_id` (PK, FK→authorizations, cascade), `session_id` (FK, cascade), `user_id`, `application_id`, `client_id`, `scopes`, `created_at`, `revoked_at`, `revoked_reason` | Grant ↔ oturum bağlantısı. Index `(session_id)`, `(user_id, client_id)`, `(application_id)` |
| `consents` | `id`, `user_id`, `client_id`, `scopes`, `granted_at`, `updated_at`, `revoked_at` | Unique `(user_id, client_id)` aktif kayıt için (filtered) |
| `user_mfa` | `user_id` (PK), `protected_secret`, `status` (Pending/Active), `created_at`, `activated_at`, `last_accepted_step` | Replay guard: `UPDATE ... WHERE last_accepted_step < @step` |
| `recovery_codes` | `id`, `user_id`, `code_hash`, `batch_id`, `created_at`, `used_at` | Tek kullanım: `UPDATE ... WHERE used_at IS NULL`. Unique `(user_id, code_hash)` |
| `mfa_challenges` | `id`, `user_id`, `created_at`, `expires_at`, `attempts`, `consumed_at`, `purpose` (Login/StepUp) | Deneme limiti atomik artış |
| `one_time_tokens` | `id`, `user_id`, `purpose` (ConfirmEmail/ResetPassword), `token_hash`, `created_at`, `expires_at`, `consumed_at` | Tek kullanım atomik `UPDATE` |
| `client_settings` | `application_id` (PK, FK), `kind` (Web/Machine/Resource), `is_disabled`, `disabled_at`, `created_at`, `created_by` | Client disable bayrağı |
| `client_secrets` | `id`, `application_id`, `secret_hash`, `created_at`, `not_after`, `revoked_at`, `created_by` | Grace penceresindeki önceki secret'lar |
| `protocol_keys` | `id`, `use` (Signing/Encryption), `kid`, `algorithm`, `status`, `protected_private_key`, `created_at`, `activated_at`, `retiring_since`, `retire_not_before`, `retired_at`, `revoked_at`, `reason` | Unique `kid`; kullanım başına tek `Active` (filtered unique index) |
| `audit_events` | `id` (bigint identity), `occurred_at`, `actor_type`, `actor_id`, `action`, `target_type`, `target_id`, `outcome`, `correlation_id`, `reason` | Salt-ekleme. Index `(occurred_at)`, `(actor_id)`, `(target_id)` |
| `outbox_messages` | `id`, `kind`, `protected_payload`, `created_at`, `available_at`, `attempts`, `lease_owner`, `lease_until`, `lease_version`, `delivered_at`, `dead_at`, `last_error_code` | Leased worker; fencing = `lease_version` |
| `data_markers` | `key`, `value` | Şema/seed işaretleri |

Hash'ler: recovery code ve tek kullanımlık token'lar ≥128 bit CSPRNG değerlerdir; `SHA-256` ile saklanır (yüksek entropili rastgele değerler için yeterli; parola değildir). Client secret'lar OpenIddict'in PBKDF2 tabanlı obfuscation'ı ile saklanır.

## 3. Transaction otoritesi

| İşlem | Atomiklik |
|---|---|
| Login (oturum oluşturma) | `user_sessions` INSERT + audit tek `SaveChanges` |
| TOTP kabulü | `user_mfa.last_accepted_step` koşullu UPDATE (rows=1 ise kabul) |
| Recovery code | `recovery_codes.used_at` koşullu UPDATE (rows=1) |
| MFA challenge tüketimi | `mfa_challenges.consumed_at` koşullu UPDATE |
| Consent + grant | consent UPSERT + authorization INSERT + `session_grants` INSERT tek transaction |
| Refresh guard | Token `TryRedeemAsync` (concurrency token) |
| Oturum/grant/kullanıcı/client iptali | Tek transaction'da toplu UPDATE (`ExecuteUpdate`) + audit |
| Parola sıfırlama | Token tüketimi (koşullu UPDATE) + parola + oturum/grant iptali tek transaction |
| Last-admin guard | `pg_advisory_xact_lock` + sayım + değişiklik tek transaction |
| Anahtar rotasyonu | `protocol_keys` durum geçişleri tek transaction (advisory lock) |
| Mail outbox | İş etkisi + outbox INSERT aynı transaction |
| Outbox lease | Aday seçimi + satır başına koşullu `UPDATE ... WHERE lease_until IS NULL OR lease_until < now` (rows=1 ise kazanıldı) + `lease_version` artışı; teslim/başarısızlık kaydı `WHERE lease_version = @v` (fencing) |
| Saklama (retention) | Zaman aşımına uğramış oturumların kapatılması + grant iptali tek transaction; silmeler yalnız kullanılamaz kayıtlar üzerinde |

## 4. Durum makineleri

```
Session:   Active ──(logout | admin revoke | password reset | user disable | idle/absolute expiry)──▶ Ended
Grant:     Valid ──(session ended | consent revoke | client disable | reuse detected | emergency)──▶ Revoked
Token:     Valid ──redeem──▶ Redeemed ──reuse──▶ (aile Revoked)      Valid ──revoke──▶ Revoked
MFA:       None ──enroll start──▶ Pending ──geçerli TOTP──▶ Active ──disable──▶ None
Key:       Active ──rotate──▶ Retiring ──retire (retire_not_before sonrası)──▶ Retired
           herhangi ──emergency──▶ Revoked
Outbox:    Pending ──lease──▶ Leased ──deliver──▶ Delivered
           Leased ──hata/expiry──▶ Pending (attempts+1) ──max──▶ Dead
```

## 5. Demo client veritabanları (`halka_pano`, `halka_rapor`)

`app_sessions`: `id` (rastgele anahtar), `protected_ticket` (DP ile şifreli auth ticket: claim'ler + token'lar), `subject`, `created_at`, `expires_at`, `version` (optimistic concurrency), `last_validated_at`. Tarayıcı cookie'si yalnız `id` taşır.

## 6. Migration politikası

- Migration'lar yalnız Migrator ile uygulanır (`migrate`), runtime uygulamalar şema değiştirmez.
- Doğrulama kapıları (testler): model snapshot uyumu ve yeniden uygulamanın no-op olması (`Migration_ModelHasNoPendingChanges_AndReapplyingIsANoOp`), Aşama 1 ve Aşama 3 şemalarından sentetik veriyle yükseltme (`Upgrade_FromTheStage1AndStage3Schemas_KeepsExistingData_AndTheResultIsUsable`), idempotent SQL script'inin boş veritabanına iki kez uygulanması ve sonucun migrator şemasıyla aynı olması (`IdempotentScript_AppliedTwice_ProducesTheSameSchemaAsTheMigrator`).
- Saklama (`RetentionService`, günlük çalışan `RetentionWorker`): önce zaman aşımına uğramış ama kapatılmamış oturumlar kapatılır (grant'leri iptal edilir); iptal edilmiş/süresi dolmuş token ve geçersiz authorization kayıtları 14 gün sonra (`Retention:Tokens`), bitmiş oturumlar, tüketilmiş/süresi dolmuş tek kullanımlık token'lar, MFA challenge'ları, teslim edilmiş outbox satırları ve süresi geçmiş eski client secret'ları 30 gün sonra (`Retention:Records`) silinir. Hâlâ yetki verebilen hiçbir kayıt silinmez. Audit silinmez (runtime rolü silemez). Demo mail sink dosyaları saklama kapsamında değildir (yerel özel dizin).
