# ZafiyetTakibi

ZafiyetTakibi; **GitHub Security Advisory** ve **Telegram kanallarından** güvenlik zafiyeti verilerini toplayan, veritabanına kaydeden, yapay zeka ile analiz eden ve web arayüzünde gösteren bir izleme sistemidir.

## Özellikler

- GitHub + Telegram kaynaklarından zafiyet toplama
- PostgreSQL üzerinde kayıt saklama
- AI destekli analiz (önem derecesi, kategori vb.)
- Web dashboard (FastAPI + Jinja2)
- Trend zafiyet kartları
- CVE tanımlı / tanımsız tablolar
- Haftalık rapor üretimi ve e-posta gönderimi
- Worker + Web süreçlerini ayrı çalıştırma

---

## Proje Yapısı

- `main.py` → Worker (toplama + analiz + zamanlama)
- `web/app.py` → Web uygulaması (FastAPI)
- `toplayicilar/` → GitHub/Telegram toplayıcıları
- `yapay_zeka/analiz.py` → AI analiz katmanı
- `modeller/` → SQLAlchemy modelleri
- `veritabani/baglanti.py` → DB bağlantısı
- `raporlama/` → Rapor üretim ve e-posta
- `web/sablonlar/` → HTML şablonları
- `web/statik/` → CSS/JS dosyaları

---

## Gereksinimler

- Python 3.11+
- PostgreSQL
- Windows PowerShell (önerilen)
- Git
