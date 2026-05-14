# ZafiyetTakibi

ZafiyetTakibi; **GitHub**, **Telegram**, **Exploit-DB**, **0day.today** ve **Google Hacking Database** gibi çok kaynaklı güvenlik zafiyeti verilerini toplayan, SQLite veritabanına kaydeden, yapay zeka ile analiz eden ve web arayüzünde gösteren otomatik bir izleme sistemidir.

## Özellikler

### Veri Kaynakları (4+ Kaynak)
- **GitHub API**: Security Advisories, CVE Issues, Vulnerability Repositories
- **Telegram**: @thehackernews, @BleepingComputer, @cveNotify, @siberbulten kanalları
- **Exploit-DB**: RSS Feed (50+ exploit/saat)
- **0day.today**: RSS Feed (zero-day exploitler)
- **Google Hacking DB**: SQL Injection, XSS, LFI vb. dork'lar

### İşlevler
- ✓ Multi-source zafiyet toplama (otomatik deduplikasyon)
- ✓ SQLite üzerinde veri depolama (7500+ zafiyet kapasitesi)
- ✓ DeepSeek AI ile analiz (önem derecesi, kategori, etkilenen yazılımlar)
- ✓ Web dashboard (FastAPI + Jinja2 + TailwindCSS)
- ✓ Haftalık rapor üretimi ve e-posta gönderimi
- ✓ Worker + Web süreçlerini ayrı çalıştırma
- ✓ Scheduled tasks (veri toplama, AI analizi, rapor gönderimi)

---

## Proje Yapısı

- `main.py` → Worker (toplama + analiz + zamanlama)
- `web/app.py` → Web uygulaması (FastAPI)
- `toplayicilar/` → GitHub/Telegram toplayıcıları
- `yapay_zeka/analiz.py` → AI analiz katmanı
- `modeller/` → SQLAlchemy modelleri
- `veritabani/baglanti.py` → SQLite bağlantısı
- `raporlama/` → Rapor üretim ve e-posta
- `web/sablonlar/` → HTML şablonları
- `web/statik/` → CSS/JS dosyaları

---

## Gereksinimler

- Python 3.11+
- Windows PowerShell (önerilen)
- Git

---

## API Endpoints - Dependency Extraction 🆕

Zafiyet açıklamalarından otomatik olarak npm packages, Python libraries, Java frameworks çıkartıp JSON olarak döndüren API endpoint'leri eklendi.

### Mevcut Endpoints

| Endpoint | Metod | Açıklama |
|----------|-------|----------|
| `/api/dependencies` | GET | Tüm dependency'leri listele |
| `/api/dependencies/{package_name}` | GET | Belirli paket detayları ve zafiyetleri |
| `/api/dependencies-by-type` | GET | Türe göre filtered dependency'ler |

### Hızlı Örnekler

```bash
# Tüm dependency'leri al
curl http://localhost:8000/api/dependencies?limit=50

# Kritik severity'ler
curl http://localhost:8000/api/dependencies?min_severity=KRITIK&limit=10

# Belirli package detayları
curl http://localhost:8000/api/dependencies/axios

# Python paketleri
curl http://localhost:8000/api/dependencies-by-type?type_filter=python
```

### Response Örneği

```json
{
  "toplam": 5,
  "kaynaklar": {
    "npm": 3,
    "python": 1,
    "java": 1
  },
  "dependencies": [
    {
      "ad": "axios",
      "tur": "npm",
      "adet": 1000,
      "max_severity": "Kritik",
      "cve_list": ["CVE-2026-40175", ...]
    }
  ]
}
```

Detaylı API belgesi: [API_DEPENDENCIES.md](API_DEPENDENCIES.md)

### İstatistikler

- **Toplam Eşsiz Dependency:** 99
- **npm Paketleri:** 45
- **Python Paketleri:** 18
- **Java Kütüphaneleri:** 18
- **PHP, Ruby, .NET:** 18

**En Riskli 5:**
1. wordpress (php) - 769 zafiyet
2. requests (python) - 578 zafiyet
3. should (npm) - 438 zafiyet
4. next (npm) - 222 zafiyet
5. fetch (npm) - 94 zafiyet
