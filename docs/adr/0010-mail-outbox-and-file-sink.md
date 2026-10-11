# ADR-0010 — DB outbox + leased worker + private dosya sink

## İhtiyaç
E-posta doğrulama ve parola sıfırlama bağlantılarının teslimi; gerçek e-posta gönderilmeden; kritik işin fire-and-forget olmaması; token'ın log/audit/admin ekranına düşmemesi.

## Seçim
- İş etkisi (kullanıcı/token kaydı) ile `outbox_messages` satırı **aynı transaction**'da yazılır. Payload (alıcı + bağlantı) Data Protection ile sarılıdır.
- `OutboxWorker` (BackgroundService): `lease_until` süresi dolmuş/bekleyen satırları koşullu UPDATE ile kiralar, `lease_version` (fencing) artırır; teslim onayı yalnız aynı `lease_version` ile yazılır. Hata → üstel bekleme ile yeniden deneme; `max_attempts` sonrası `dead_at` (DLQ). Kiracı çökerse lease süresi dolunca başka çalışan devralır.
- **Sink**: `Mail:SinkDirectory` altına `<message-id>.json` (idempotent: aynı id yeniden yazılabilir). Yerelde `.local/mail-sink/` (git'te yok). Admin UI'da içerik gösterilmez; yalnız kuyruk sayıları görünür. Böylece admin, kullanıcının reset bağlantısını okuyamaz.

## Daha basit alternatif
İstek içinde senkron dosya yazma: worker gerekmez ama gerçek sağlayıcıya geçişte güvenilirlik deseni olmaz ve yanıt süresi kullanıcı varlığına göre daha çok değişir.

## Maliyet
Bir tablo + bir worker + testleri.

## Sınır
Gerçek SMTP/sağlayıcı yok; teslim "en az bir kez"dir (sink idempotent olduğu için sorun değil). Tek worker instance doğrulandı; lease mekanizması çoklu çalışanı destekleyecek şekilde yazıldı.

## Değişme koşulu
Gerçek e-posta sağlayıcısı: sink arayüzü (`IMailSink`) değiştirilir, outbox aynı kalır.
