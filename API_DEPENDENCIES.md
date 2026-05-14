# Dependency Extraction API Documentation

## Overview
Zafiyet açıklamalarından otomatik olarak npm packages, Python libraries, Java frameworks ve diğer dependency'leri çıkartıp API aracılığıyla JSON olarak döndüren sistem.

## API Endpoints

### 1. GET `/api/dependencies`
Tüm extracted dependency'leri listeler ve zafiyet sayısına göre sıralar.

**Query Parameters:**
- `limit` (int, default: 50) - Maksimum kaç sonuç döneceğini belirtir
- `min_severity` (str, optional) - Minimum önem seviyesi filtresi: KRITIK, YUKSEK, ORTA, DUSUK, BILGI

**Response:**
```json
{
  "toplam": 5,
  "kaynaklar": {
    "npm": 3,
    "python": 1,
    "java": 1,
    "ruby": 0,
    "php": 0,
    "dotnet": 0
  },
  "dependencies": [
    {
      "ad": "axios",
      "version": "0.21.1",
      "tur": "npm",
      "adet": 1000,
      "max_severity": "Kritik",
      "cve_list": ["CVE-2026-40175", ...]
    },
    ...
  ],
  "son_guncelleme": "2026-05-13T19:02:33.839259"
}
```

**Example:**
```bash
curl http://localhost:8000/api/dependencies?limit=10&min_severity=KRITIK
```

---

### 2. GET `/api/dependencies/{package_name}`
Belirli bir dependency'nin detaylı bilgisini ve ilişkili zafiyetleri döndürür.

**Path Parameters:**
- `package_name` (str) - Paket adı (örn: axios, django, spring-core)

**Response:**
```json
{
  "ad": "axios",
  "version": null,
  "tur": "npm",
  "toplam_zafiyetler": 35,
  "max_severity": "Kritik",
  "cve_list": ["CVE-2026-40175"],
  "zafiyetler": [
    {
      "id": 226,
      "baslik": "NxAppWebpackPlugin generatePackageJson...",
      "kaynak": "GitHub",
      "onem": "Yüksek",
      "kategori": "Diger",
      "cve": null
    },
    ...
  ],
  "son_guncelleme": "2026-05-13T19:03:04.665371"
}
```

**Example:**
```bash
curl http://localhost:8000/api/dependencies/axios
curl http://localhost:8000/api/dependencies/django
curl http://localhost:8000/api/dependencies/spring-core
```

---

### 3. GET `/api/dependencies-by-type`
Türe göre gruplanmış tüm dependency'leri döndürür.

**Query Parameters:**
- `type_filter` (str, default: npm) - Paket türü: npm, python, java, ruby, php, dotnet

**Response:**
```json
{
  "tur": "python",
  "toplam": 18,
  "dependencies": [
    {
      "ad": "requests",
      "version": null,
      "adet": 578,
      "max_severity": "Kritik",
      "cve_list": ["CVE-2025-9901", ...]
    },
    ...
  ],
  "son_guncelleme": "2026-05-13T19:03:45.123456"
}
```

**Example:**
```bash
curl http://localhost:8000/api/dependencies-by-type?type_filter=python
curl http://localhost:8000/api/dependencies-by-type?type_filter=java
curl http://localhost:8000/api/dependencies-by-type?type_filter=npm
```

---

## Supported Package Types

| Tür | Paketler | Örnekler |
|-----|----------|---------|
| **npm** | Node.js packages | axios, express, react, webpack, TypeScript, lodash, jest, etc. |
| **python** | Python packages | flask, django, requests, sqlalchemy, pandas, numpy, tensorflow, etc. |
| **java** | Java libraries | spring-core, commons-io, log4j, junit, jackson, hibernate, etc. |
| **ruby** | Ruby gems | rails, sinatra, devise, bundler, rspec, capistrano, etc. |
| **php** | Composer packages | laravel, symfony, wordpress, drupal, doctrine, etc. |
| **dotnet** | .NET/C# packages | asp.net, entity-framework, newtonsoft.json, automapper, etc. |

---

## Extraction Patterns

API, zafiyet açıklamalarından aşağıdaki paketleri otomatik olarak tanır:

### NPM Packages (45 paket bulundu)
axios, express, react, vue, angular, webpack, typescript, lodash, jquery, moment, chalk, jest, mocha, cypress, eslint, prettier, babel, rollup, vite, next, nuxt, nest, fastapi, etc.

### Python Packages (18 paket bulundu)
flask, django, requests, sqlalchemy, celery, pytest, pandas, numpy, scipy, scikit-learn, matplotlib, seaborn, jupyter, tensorflow, pytorch, beautifulsoup, selenium, scrapy, etc.

### Java Libraries (18 paket bulundu)
spring-core, commons-io, log4j, slf4j, junit, mockito, jackson, gson, hibernate, etc.

### Ruby Gems (5 paket bulundu)
rails, sinatra, devise, bundler, rspec, etc.

### PHP Packages (10 paket bulundu)
laravel, symfony, wordpress, drupal, magento, doctrine, swiftmailer, etc.

### .NET/C# (3 paket bulundu)
asp.net, entity-framework, newtonsoft.json, etc.

---

## Statistics

Mevcut Database İstatistikleri:
- **Toplam Eşsiz Dependency:** 99
- **Zafiyet İçeren Kayıtlar:** 7,588
- **Toplam Eşleşen CVE:** Binlerce

### Top 5 En Riskli Dependency

| Rank | Paket | Tür | Zafiyet | Max Severity |
|------|-------|-----|---------|--------------|
| 1 | wordpress | php | 769 | Kritik |
| 2 | requests | python | 578 | Kritik |
| 3 | should | npm | 438 | Kritik |
| 4 | next | npm | 222 | Kritik |
| 5 | fetch | npm | 94 | Kritik |

---

## Usage Examples

### Python
```python
import requests

# 1. Get top 10 dependencies
response = requests.get('http://localhost:8000/api/dependencies?limit=10')
deps = response.json()

# 2. Get specific package details
response = requests.get('http://localhost:8000/api/dependencies/axios')
axios_info = response.json()

# 3. Get all Python packages
response = requests.get('http://localhost:8000/api/dependencies-by-type?type_filter=python')
python_deps = response.json()
```

### JavaScript/Node.js
```javascript
// 1. Fetch all dependencies
const response = await fetch('http://localhost:8000/api/dependencies?limit=20');
const data = await response.json();

// 2. Get vulnerability info for specific package
const pkg = await fetch('http://localhost:8000/api/dependencies/react');
const reactVulns = await pkg.json();

// 3. List by type
const npmPkgs = await fetch('http://localhost:8000/api/dependencies-by-type?type_filter=npm');
const npmData = await npmPkgs.json();
```

### cURL
```bash
# Get all dependencies
curl -s http://localhost:8000/api/dependencies?limit=50 | jq '.dependencies | length'

# Get axios vulnerabilities
curl -s http://localhost:8000/api/dependencies/axios | jq '.toplam_zafiyetler'

# Get only critical Python packages
curl -s 'http://localhost:8000/api/dependencies-by-type?type_filter=python' | jq '.dependencies[] | select(.max_severity=="Kritik")'
```

---

## Response Codes

| Code | Meaning |
|------|---------|
| 200 | Success - Data returned |
| 404 | Not Found - Package name doesn't exist |
| 500 | Server Error |

---

## Notes

- API, vulnerability descriptions'larından otomatik pattern matching kullanarak packages tanır
- Aynı package birden çok versiyonla bulunabilir
- CVE listesi her zafiyet kaydında ayrıca tutulur
- API cache yapılmamıştır ve her request'te database sorgulanır
- Büyük dataset'ler için pagination önerilir

---

## Integration with Monitoring

Bu API, aşağıdaki iş akışlarında kullanılabilir:

1. **Dependency Audit** - Projedeki paketlerin ne kadar zafiyet içerdiğini kontrol etme
2. **Supply Chain Security** - npm/PyPI paket kompromislerini takip etme
3. **Risk Dashboard** - En riskli paketleri real-time izleme
4. **Automated Alerts** - Yeni zafiyet'ler tetiklediğinde bildirim gönderme

