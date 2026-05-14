
import sys
import os
from datetime import datetime, timedelta
import re
import asyncio
from typing import List
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from sqlalchemy import func, and_

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
sys.path.insert(0, PROJECT_ROOT)

from raporlama.rapor_olustur import RaporOlusturucu
from raporlama.mail_gonder import MailGonderici
from veritabani.baglanti import session_al, veritabanini_hazirla
from modeller.zafiyet import Zafiyet, OnemDerecesi
from yapay_zeka.analiz import ZafiyetAnalizci
from modeller.abone import Abone

app = FastAPI(title="Zafiyet Takip Sistemi")

STATIC_DIR = os.path.join(BASE_DIR, "statik")
TEMPLATE_DIR = os.path.join(BASE_DIR, "sablonlar")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "raporlar")
os.makedirs(REPORTS_DIR, exist_ok=True)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
REMOTE_PATTERN = re.compile(
    r"\b(remote|rce|uzaktan|remote code execution|command injection|auth(entication)? bypass)\b",
    re.IGNORECASE,
)
ANLAMSIZ_TREND_ETIKETLERI = {"diger", "bilinmiyor", "unknown", "genel"}
PINLI_TREND_TERIMLERI = ("litellm",)

if not os.path.exists(STATIC_DIR):
    raise FileNotFoundError(f" Static klasörü bulunamadı: {STATIC_DIR}")
if not os.path.exists(TEMPLATE_DIR):
    raise FileNotFoundError(f" Template klasörü bulunamadı: {TEMPLATE_DIR}")

app.mount("/statik", StaticFiles(directory=STATIC_DIR), name="statik")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

# === CORS Setup ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tüm origin'lere izin ver
    allow_credentials=True,
    allow_methods=["*"],  # GET, POST, PUT, DELETE, etc.
    allow_headers=["*"],  # Tüm headerları kabul et
)

_monitor_task = None


def _analizli_query(db):
    return db.query(Zafiyet).filter(Zafiyet.onem_derecesi.isnot(None))


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f" Yeni bağlantı. Aktif: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f" Bağlantı koptu. Aktif: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f" Gönderim hatası: {e}")
                dead_connections.append(connection)

        for conn in dead_connections:
            if conn in self.active_connections:
                self.active_connections.remove(conn)


manager = ConnectionManager()


class AboneEkleModel(BaseModel):
    ad_soyad: str
    email: str

    @field_validator("ad_soyad")
    @classmethod
    def ad_soyad_bos_olamaz(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Ad Soyad boş olamaz")
        return v

    @field_validator("email")
    @classmethod
    def email_dogrula(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_PATTERN.match(v):
            raise ValueError("Geçersiz email")
        return v


class RaporGonderModel(BaseModel):
    dosya_adi: str
    konu: str | None = None


class DependencyModel(BaseModel):
    """Dependency/Paket Modeli"""
    ad: str
    version: str | None = None
    tur: str  # npm, python, java, ruby, php, dotnet, diğer
    adet: int = 1  # Kaç zafiyette kullanıldığı
    max_severity: str | None = None  # En yüksek önem derecesi
    cve_list: List[str] | None = None  # İlişkili CVE'ler
    zafiyetler: List[dict] | None = None  # Zafiyet özeti


class DependenciesResponseModel(BaseModel):
    """API Yanıtı"""
    toplam: int
    kaynaklar: dict  # Kaynak türüne göre gruplama
    dependencies: List[DependencyModel]
    en_risk_li: List[DependencyModel] | None = None
    son_guncelleme: datetime


@app.on_event("startup")
async def startup_event():
    global _monitor_task
    veritabanini_hazirla()
    if _monitor_task is None or _monitor_task.done():
        _monitor_task = asyncio.create_task(monitor_database())
    print(" Startup tamamlandı (DB + monitor aktif)")


def cve_var_mi(text):
    if not text:
        return False
    if isinstance(text, str) and text.strip() == "":
        return False
    return bool(CVE_PATTERN.search(str(text)))


def cve_numarasi_bul(zafiyet):
    if zafiyet.cve_numarasi and CVE_PATTERN.search(str(zafiyet.cve_numarasi)):
        return CVE_PATTERN.search(str(zafiyet.cve_numarasi)).group(0).upper()

    if zafiyet.baslik and CVE_PATTERN.search(str(zafiyet.baslik)):
        return CVE_PATTERN.search(str(zafiyet.baslik)).group(0).upper()

    if zafiyet.aciklama and CVE_PATTERN.search(str(zafiyet.aciklama)):
        return CVE_PATTERN.search(str(zafiyet.aciklama)).group(0).upper()

    return None


def remote_zafiyet_mi(zafiyet) -> bool:
    alanlar = [
        zafiyet.baslik,
        zafiyet.aciklama,
        zafiyet.kategori,
        zafiyet.etkilenen_yazilimlar,
    ]
    metin = " ".join([str(a) for a in alanlar if a])
    if not metin:
        return False
    return bool(REMOTE_PATTERN.search(metin))


def _anahtar_kelime_bul(baslik: str) -> str:
    metin = (baslik or "").lower()
    metin = re.sub(r"cve-\d{4}-\d{4,7}", " ", metin, flags=re.IGNORECASE)

    adaylar = re.findall(r"[a-z0-9][a-z0-9+._-]{2,}", metin)
    stop = {
        "vulnerability", "security", "advisory", "update", "patch", "bug",
        "issue", "critical", "high", "medium", "low", "remote", "code",
        "execution", "rce", "xss", "sql", "injection", "disclosure",
        "dos", "bypass", "overflow", "exploit", "auth", "authentication",
        "zafiyet", "guvenlik", "açığı", "acigi", "kritik", "yuksek", "orta", "dusuk",
        "new", "latest", "breaking", "alert", "the", "this", "that", "popular", "malicious"
    }
    for t in adaylar:
        if t.isdigit():
            continue
        if not re.search(r"[a-z]", t):
            continue
        if t not in stop:
            return t
    return "diger"


def _urun_etiketi_bul(zafiyet) -> str:
    yazilim = (zafiyet.etkilenen_yazilimlar or "").strip().lower()
    if yazilim and yazilim not in {"-", "bilinmiyor", "unknown"}:
        aday = re.split(r"[,/|;]", yazilim, maxsplit=1)[0].strip()
        aday = re.sub(r"\s+", " ", aday)
        aday = re.sub(r"\b(v\d+[\w.-]*|\d+[\w.-]*)\b", "", aday).strip()
        if len(aday) >= 3 and re.search(r"[a-z]", aday):
            return aday

    metin = " ".join([
        zafiyet.baslik or "",
        zafiyet.aciklama or "",
        zafiyet.kategori or "",
        zafiyet.url or "",
    ]).lower()

    for terim in PINLI_TREND_TERIMLERI:
        if re.search(rf"\b{re.escape(terim)}\b", metin):
            return terim

    return _anahtar_kelime_bul(zafiyet.baslik or "")


def _trend_sirala(trend_gruplari: dict, limit: int = 10) -> list:
    sirali = sorted(
        trend_gruplari.values(),
        key=lambda x: (x["adet"], x["son_tarih"] or datetime.min),
        reverse=True,
    )

    anlamli = [
        g for g in sirali
        if (g.get("grup_etiketi") or "").strip().lower() not in ANLAMSIZ_TREND_ETIKETLERI
    ]
    secilen = anlamli[:limit]

    if len(secilen) < limit:
        secili_anahtarlar = {s.get("anahtar") for s in secilen}
        for aday in sirali:
            if len(secilen) >= limit:
                break
            if aday.get("anahtar") in secili_anahtarlar:
                continue
            secilen.append(aday)
            secili_anahtarlar.add(aday.get("anahtar"))

    secili_anahtarlar = {s.get("anahtar") for s in secilen}
    for terim in PINLI_TREND_TERIMLERI:
        aday = next(
            (
                g for g in sirali
                if terim in (g.get("grup_etiketi") or "").lower()
                or terim in (g.get("yazilim") or "").lower()
                or terim in (g.get("baslik") or "").lower()
            ),
            None,
        )
        if not aday or aday.get("anahtar") in secili_anahtarlar:
            continue
        if len(secilen) < limit:
            secilen.append(aday)
        else:
            secilen[-1] = aday
        secili_anahtarlar = {s.get("anahtar") for s in secilen}

    return secilen


def _onem_sira(onem) -> int:
    if onem == OnemDerecesi.KRITIK:
        return 5
    elif onem == OnemDerecesi.YUKSEK:
        return 4
    elif onem == OnemDerecesi.ORTA:
        return 3
    elif onem == OnemDerecesi.DUSUK:
        return 2
    elif onem == OnemDerecesi.BILGI:
        return 1
    return 0


# ============= DEPENDENCY EXTRACTION =============
def extract_dependencies(metin: str) -> List[dict]:
    """Zafiyetlerden dependency'leri çıkart"""
    if not metin:
        return []
    
    dependencies = []
    metin_lower = metin.lower()
    
    # NPM Packages - axios, express, react, webpack, etc.
    npm_pattern = r'\b(axios|express|react|vue|angular|webpack|typescript|lodash|jquery|moment|chalk|jest|mocha|cypress|eslint|prettier|babel|rollup|vite|next|nuxt|nest|fastify|hapi|koa|ejs|handlebars|pug|sass|less|postcss|pm2|forever|nodemon|dotenv|jsonwebtoken|bcrypt|passport|cors|helmet|compression|multer|socket\.io|ws|mqtt|amqp|redis|mongodb|mongoose|sequelize|typeorm|knex|prisma|graphql|apollo|relay|fetch|axios|supertest|sinon|chai|should)\b(?:[\s@=^>~-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][a-z0-9]+)?)?)?'
    
    for match in re.finditer(npm_pattern, metin_lower):
        dep_name = match.group(1)
        version = match.group(2) if len(match.groups()) > 1 else None
        dependencies.append({
            'ad': dep_name,
            'version': version,
            'tur': 'npm',
            'materyel': match.group(0)
        })
    
    # Python Packages - flask, django, requests, sqlalchemy, etc.
    python_pattern = r'\b(flask|django|requests|sqlalchemy|celery|pytest|pandas|numpy|scipy|scikit-learn|matplotlib|seaborn|jupyter|tensorflow|pytorch|keras|beautifulsoup|selenium|scrapy|fastapi|starlette|pydantic|sqlmodel|tortoise|peewee|alembic|black|pylint|flake8|mypy|poetry|pipenv)\b(?:[\s=<>~-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?)?'
    
    for match in re.finditer(python_pattern, metin_lower):
        dep_name = match.group(1)
        version = match.group(2) if len(match.groups()) > 1 else None
        dependencies.append({
            'ad': dep_name,
            'version': version,
            'tur': 'python',
            'materyel': match.group(0)
        })
    
    # Java Libraries - spring-core, commons-io, jboss-logging, etc.
    java_pattern = r'\b(spring-(?:core|web|boot|security|cloud|data|mvc|expression)|commons-(?:io|lang|codec|logging|collections)|log4j|slf4j|jboss-logging|junit|mockito|jackson|gson|hibernate|jpa|maven|gradle|tomcat|jetty|netty|undertow|wildfly|xstream)\b(?:[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)?)?'
    
    for match in re.finditer(java_pattern, metin_lower):
        dep_name = match.group(1)
        version = match.group(2) if len(match.groups()) > 1 else None
        dependencies.append({
            'ad': dep_name,
            'version': version,
            'tur': 'java',
            'materyel': match.group(0)
        })
    
    # Ruby Gems - rails, sinatra, devise, etc.
    ruby_pattern = r'\b(rails|sinatra|devise|pundit|sidekiq|resque|bundler|rake|thor|rspec|capistrano|puma|unicorn|thin|webrick)\b(?:[\s~>=-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?)?'
    
    for match in re.finditer(ruby_pattern, metin_lower):
        dep_name = match.group(1)
        version = match.group(2) if len(match.groups()) > 1 else None
        dependencies.append({
            'ad': dep_name,
            'version': version,
            'tur': 'ruby',
            'materyel': match.group(0)
        })
    
    # PHP Composer - laravel, symfony, wordpress, etc.
    php_pattern = r'\b(laravel|symfony|wordpress|drupal|magento|composer|doctrine|monolog|swiftmailer|phpunit|guzzle|slim|yii|zend|phalcon|cakephp|code-igniter)\b(?:[\s~>=-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?)?'
    
    for match in re.finditer(php_pattern, metin_lower):
        dep_name = match.group(1)
        version = match.group(2) if len(match.groups()) > 1 else None
        dependencies.append({
            'ad': dep_name,
            'version': version,
            'tur': 'php',
            'materyel': match.group(0)
        })
    
    # .NET/C# - asp.net, entity-framework, nuget packages
    dotnet_pattern = r'\b(asp\.net|entity-framework|linq|newtonsoft\.json|automapper|ninject|unity|autofac|structuremap|log4net|nlog|serilog|xunit|nsubstitute|moq)\b(?:[\s.~>=-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?)?'
    
    for match in re.finditer(dotnet_pattern, metin_lower):
        dep_name = match.group(1)
        version = match.group(2) if len(match.groups()) > 1 else None
        dependencies.append({
            'ad': dep_name,
            'version': version,
            'tur': 'dotnet',
            'materyel': match.group(0)
        })
    
    return dependencies


def aggregate_dependencies(db_session) -> dict:
    """Veritabanındaki tüm zafiyetlerden dependency'leri topla"""
    all_deps = {}
    all_zafiyetler = db_session.query(Zafiyet).all()
    
    for zafiyet in all_zafiyetler:
        # Başlık, açıklama ve kategoriden dependency'leri çıkart
        metin = f"{zafiyet.baslik or ''} {zafiyet.aciklama or ''} {zafiyet.etkilenen_yazilimlar or ''}"
        deps = extract_dependencies(metin)
        
        for dep in deps:
            key = f"{dep['ad']}-{dep['tur']}"
            if key not in all_deps:
                all_deps[key] = {
                    'ad': dep['ad'],
                    'version': dep['version'],
                    'tur': dep['tur'],
                    'adet': 0,
                    'zafiyetler_ids': [],
                    'max_severity': None,  # OnemDerecesi Enum
                    'cve_list': set()
                }
            
            all_deps[key]['adet'] += 1
            if zafiyet.id not in all_deps[key]['zafiyetler_ids']:
                all_deps[key]['zafiyetler_ids'].append(zafiyet.id)
            
            # En yüksek önem seviyesini sakla
            if zafiyet.onem_derecesi:
                current_severity = _onem_sira(zafiyet.onem_derecesi)
                if all_deps[key]['max_severity'] is None:
                    all_deps[key]['max_severity'] = zafiyet.onem_derecesi
                else:
                    existing_severity = _onem_sira(all_deps[key]['max_severity'])
                    if current_severity > existing_severity:
                        all_deps[key]['max_severity'] = zafiyet.onem_derecesi
            
            # CVE'leri sakla
            cve = cve_numarasi_bul(zafiyet)
            if cve:
                all_deps[key]['cve_list'].add(cve)
    
    return all_deps


def _guvenli_rapor_yolu(dosya_adi: str) -> str | None:
    safe_name = os.path.basename(dosya_adi)
    if safe_name != dosya_adi or not safe_name.lower().endswith(".html"):
        return None
    tam_yol = os.path.abspath(os.path.join(REPORTS_DIR, safe_name))
    if not tam_yol.startswith(os.path.abspath(REPORTS_DIR)):
        return None
    return tam_yol


@app.get("/", response_class=HTMLResponse)
async def anasayfa(request: Request):
    try:
        db = session_al()
    except Exception as e:
        print(f"Veritabanı bağlantı hatası: {e}")
        return HTMLResponse(
            content="<h1>Veritabanı Bağlantı Hatası</h1><p>Lütfen PostgreSQL'in çalıştığından emin olun.</p>",
            status_code=500
        )

    try:
        q = _analizli_query(db)

        toplam = q.count()
        kritik = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.KRITIK).count()
        yuksek = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.YUKSEK).count()
        orta = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.ORTA).count()
        dusuk = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.DUSUK).count()

        analiz_edilmis = toplam
        analiz_bekleyen = db.query(Zafiyet).filter(Zafiyet.onem_derecesi.is_(None)).count()

        tum_zafiyetler = q.order_by(Zafiyet.bulunan_tarih.desc()).all()

        cve_var_sayisi = 0
        cve_yok_sayisi = 0
        cve_zafiyetler_liste = []
        cvesiz_zafiyetler_liste = []
        remote_kritik_zafiyetler = []

        for zafiyet in tum_zafiyetler:
            has_cve = (
                cve_var_mi(zafiyet.cve_numarasi) or
                cve_var_mi(zafiyet.baslik) or
                cve_var_mi(zafiyet.aciklama)
            )
            if has_cve:
                cve_var_sayisi += 1
                zafiyet.extracted_cve = cve_numarasi_bul(zafiyet)
                cve_zafiyetler_liste.append(zafiyet)
            else:
                cve_yok_sayisi += 1
                cvesiz_zafiyetler_liste.append(zafiyet)

            if zafiyet.onem_derecesi == OnemDerecesi.KRITIK and remote_zafiyet_mi(zafiyet):
                zafiyet.extracted_cve = cve_numarasi_bul(zafiyet)
                remote_kritik_zafiyetler.append(zafiyet)

        cve_zafiyetler = cve_zafiyetler_liste[:100]
        cvesiz_zafiyetler = cvesiz_zafiyetler_liste[:100]
        remote_kritik_zafiyetler = remote_kritik_zafiyetler[:20]


        # Tüm veri kaynakları için istatistik
        kaynak_istatistikleri = db.query(
            Zafiyet.kaynak,
            func.count(Zafiyet.id).label("adet")
        ).group_by(Zafiyet.kaynak).all()
        
        kaynak_verisi = {}
        for kaynak, adet in kaynak_istatistikleri:
            if kaynak:
                kaynak_verisi[kaynak] = adet
        
        github_sayisi = kaynak_verisi.get("GitHub", 0)
        telegram_sayisi = kaynak_verisi.get("Telegram", 0)
        exploit_db_sayisi = kaynak_verisi.get("Exploit-DB", 0)
        zeday_sayisi = kaynak_verisi.get("0day.today", 0)

        yedi_gun_once = datetime.now() - timedelta(days=7)

        trend_kayitlari = q.filter(
            and_(
                Zafiyet.baslik.isnot(None),
                Zafiyet.baslik != "",
                Zafiyet.bulunan_tarih >= yedi_gun_once
            )
        ).all()

        trend_gruplari = {}
        for z in trend_kayitlari:
            cve = cve_numarasi_bul(z)
            if cve:
                anahtar = f"cve:{cve}"
                grup_etiketi = cve
            else:
                urun_etiketi = _urun_etiketi_bul(z)
                anahtar = f"urun:{urun_etiketi}"
                grup_etiketi = urun_etiketi

            if anahtar not in trend_gruplari:
                trend_gruplari[anahtar] = {
                    "anahtar": anahtar,
                    "grup_etiketi": grup_etiketi,
                    "baslik": z.baslik or "",
                    "aciklama": z.aciklama or "",
                    "kategori": z.kategori or "Belirsiz",
                    "adet": 0,
                    "kaynak": z.kaynak,
                    "yazilim": z.etkilenen_yazilimlar or "-",
                    "max_onem": z.onem_derecesi,
                    "son_tarih": z.bulunan_tarih,
                    "url": z.url,
                    "onem_skor": _onem_sira(z.onem_derecesi),
                }

            g = trend_gruplari[anahtar]
            g["adet"] += 1

            if z.bulunan_tarih and (not g["son_tarih"] or z.bulunan_tarih > g["son_tarih"]):
                g["baslik"] = z.baslik or g["baslik"]
                g["aciklama"] = z.aciklama or g["aciklama"]
                g["kategori"] = z.kategori or g["kategori"]
                g["kaynak"] = z.kaynak or g["kaynak"]
                g["yazilim"] = z.etkilenen_yazilimlar or g["yazilim"]
                g["son_tarih"] = z.bulunan_tarih
                g["url"] = z.url or g["url"]

            skor = _onem_sira(z.onem_derecesi)
            if skor > g["onem_skor"]:
                g["max_onem"] = z.onem_derecesi
                g["onem_skor"] = skor

        trend_sirali = _trend_sirala(trend_gruplari, limit=10)

        try:
            analizci = ZafiyetAnalizci()
            ai_kullanilabilir = True
        except Exception as e:
            print(f" AI başlatılamadı: {e}")
            ai_kullanilabilir = False

        trend_zafiyetler = []
        for trend in trend_sirali:
            orijinal_baslik = trend["baslik"]
            if ai_kullanilabilir:
                try:
                    zafiyet_metni = f"{trend['baslik']}\n{trend.get('aciklama') or ''}\nKategori: {trend.get('kategori') or 'Belirsiz'}\nYazılım: {trend.get('yazilim') or '-'}"
                    ai_baslik = analizci.baslik_uret(zafiyet_metni)
                    baslik = ai_baslik if ai_baslik else orijinal_baslik
                except Exception:
                    baslik = orijinal_baslik
            else:
                baslik = orijinal_baslik

            trend_zafiyetler.append({
                "baslik": baslik,
                "orijinal_baslik": orijinal_baslik,
                "kategori": trend.get("kategori") or "Belirsiz",
                "adet": trend.get("adet", 0),
                "kaynak": trend.get("kaynak"),
                "yazilim": trend.get("yazilim") or "-",
                "max_onem": trend["max_onem"].value if trend.get("max_onem") else "Bilinmiyor",
                "son_tarih": trend["son_tarih"].strftime("%d.%m.%Y") if trend.get("son_tarih") else "-",
                "url": trend.get("url")
            })

        son_7_gun = q.filter(Zafiyet.bulunan_tarih >= yedi_gun_once).count()

        kategoriler = q.with_entities(
            Zafiyet.kategori,
            func.count(Zafiyet.id).label("adet")
        ).filter(
            and_(Zafiyet.kategori.isnot(None), Zafiyet.kategori != "")
        ).group_by(
            Zafiyet.kategori
        ).order_by(
            func.count(Zafiyet.id).desc()
        ).limit(5).all()

        return templates.TemplateResponse("anasayfa.html", {
            "request": request,
            "toplam": toplam,
            "kritik": kritik,
            "yuksek": yuksek,
            "orta": orta,
            "dusuk": dusuk,
            "analiz_edilmis": analiz_edilmis,
            "analiz_bekleyen": analiz_bekleyen,
            "cve_var": cve_var_sayisi,
            "cve_yok": cve_yok_sayisi,
            "github_sayisi": github_sayisi,
            "telegram_sayisi": telegram_sayisi,
            "exploit_db_sayisi": exploit_db_sayisi,
            "zeday_sayisi": zeday_sayisi,
            "kaynak_verisi": kaynak_verisi,
            "cve_zafiyetler": cve_zafiyetler,
            "cvesiz_zafiyetler": cvesiz_zafiyetler,
            "remote_kritik_zafiyetler": remote_kritik_zafiyetler,
            "remote_kritik_sayisi": len(remote_kritik_zafiyetler),
            "trend_zafiyetler": trend_zafiyetler,
            "son_7_gun": son_7_gun,
            "kategoriler": kategoriler
        })
    except Exception as e:
        print(f" Sorgu hatası: {e}")
        return HTMLResponse(content=f"<h1>Hata</h1><pre>{str(e)}</pre>", status_code=500)
    finally:
        db.close()


@app.get("/raporlar", response_class=HTMLResponse)
async def raporlar_sayfasi(request: Request):
    return templates.TemplateResponse("raporlar.html", {"request": request})


@app.get("/api/zafiyetler")
async def zafiyetler_listesi(onem: str = None, kategori: str = None, yazilim: str = None, limit: int = 50, offset: int = 0):
    db = session_al()
    try:
        query = _analizli_query(db)

        if onem:
            try:
                query = query.filter(Zafiyet.onem_derecesi == OnemDerecesi[onem.upper()])
            except KeyError:
                pass

        if kategori:
            query = query.filter(Zafiyet.kategori.ilike(f"%{kategori}%"))

        if yazilim:
            query = query.filter(Zafiyet.etkilenen_yazilimlar.ilike(f"%{yazilim}%"))

        toplam = query.count()
        zafiyetler = query.order_by(Zafiyet.bulunan_tarih.desc()).limit(limit).offset(offset).all()

        return {
            "toplam": toplam,
            "limit": limit,
            "offset": offset,
            "zafiyetler": [
                {
                    "id": z.id,
                    "baslik": z.baslik,
                    "kaynak": z.kaynak,
                    "cve_numarasi": cve_numarasi_bul(z),
                    "cve_var": cve_var_mi(z.cve_numarasi) or cve_var_mi(z.baslik) or cve_var_mi(z.aciklama),
                    "onem_derecesi": z.onem_derecesi.value if z.onem_derecesi else "Bilinmiyor",
                    "kategori": z.kategori or "-",
                    "etkilenen_yazilimlar": z.etkilenen_yazilimlar or "-",
                    "bulunan_tarih": z.bulunan_tarih.isoformat() if z.bulunan_tarih else None,
                    "url": z.url
                }
                for z in zafiyetler
            ]
        }
    finally:
        db.close()


@app.get("/api/istatistikler")
async def istatistikler():
    db = session_al()
    try:
        q = _analizli_query(db)
        toplam = q.count()
        kritik = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.KRITIK).count()
        yuksek = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.YUKSEK).count()
        orta = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.ORTA).count()
        dusuk = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.DUSUK).count()

        yedi_gun_once = datetime.now() - timedelta(days=7)
        son_7_gun = q.filter(Zafiyet.bulunan_tarih >= yedi_gun_once).count()

        return {
            "toplam": toplam,
            "kritik": kritik,
            "yuksek": yuksek,
            "orta": orta,
            "dusuk": dusuk,
            "son_7_gun": son_7_gun
        }
    finally:
        db.close()


@app.get("/api/kategori-grafik")
async def kategori_grafik():
    db = session_al()
    try:
        kategoriler = _analizli_query(db).with_entities(
            Zafiyet.kategori, func.count(Zafiyet.id).label("adet")
        ).filter(
            and_(Zafiyet.kategori.isnot(None), Zafiyet.kategori != "")
        ).group_by(
            Zafiyet.kategori
        ).order_by(
            func.count(Zafiyet.id).desc()
        ).limit(10).all()

        return {"labels": [k.kategori for k in kategoriler], "values": [k.adet for k in kategoriler]}
    finally:
        db.close()


@app.get("/api/onem-grafik")
async def onem_grafik():
    db = session_al()
    try:
        q = _analizli_query(db)
        kritik = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.KRITIK).count()
        yuksek = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.YUKSEK).count()
        orta = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.ORTA).count()
        dusuk = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.DUSUK).count()

        labels, values, colors = [], [], []

        if kritik > 0:
            labels.append("Kritik"); values.append(kritik); colors.append("#dc2626")
        if yuksek > 0:
            labels.append("Yüksek"); values.append(yuksek); colors.append("#ea580c")
        if orta > 0:
            labels.append("Orta"); values.append(orta); colors.append("#f59e0b")
        if dusuk > 0:
            labels.append("Düşük"); values.append(dusuk); colors.append("#10b981")

        return {"labels": labels, "values": values, "colors": colors}
    finally:
        db.close()


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Zafiyet Takip Sistemi"
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    db = None
    try:
        db = session_al()
        q = _analizli_query(db)
        toplam = q.count()
        kritik = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.KRITIK).count()
        yuksek = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.YUKSEK).count()
        orta = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.ORTA).count()
        dusuk = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.DUSUK).count()

        yedi_gun_once = datetime.now() - timedelta(days=7)
        son_7_gun = q.filter(Zafiyet.bulunan_tarih >= yedi_gun_once).count()

        await websocket.send_json({
            "type": "initial_stats",
            "data": {
                "toplam": toplam,
                "kritik": kritik,
                "yuksek": yuksek,
                "orta": orta,
                "dusuk": dusuk,
                "son_7_gun": son_7_gun
            }
        })
    except Exception as e:
        print(f"İlk veri gönderme hatası: {e}")
    finally:
        if db:
            db.close()

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f" WebSocket hatası: {e}")
        manager.disconnect(websocket)


async def monitor_database():
    last_count = 0
    last_id = 0

    db = None
    try:
        db = session_al()
        q = _analizli_query(db)
        last_count = q.count()
        latest = q.order_by(Zafiyet.id.desc()).first()
        if latest:
            last_id = latest.id
    except Exception as e:
        print(f"İlk kontrol hatası: {e}")
    finally:
        if db:
            db.close()

    while True:
        try:
            await asyncio.sleep(5)

            if not manager.active_connections:
                continue

            db = session_al()
            q = _analizli_query(db)
            current_count = q.count()

            if current_count > last_count:
                latest = q.filter(Zafiyet.id > last_id).order_by(Zafiyet.id.desc()).first()

                if latest:
                    kritik = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.KRITIK).count()
                    yuksek = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.YUKSEK).count()
                    orta = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.ORTA).count()
                    dusuk = q.filter(Zafiyet.onem_derecesi == OnemDerecesi.DUSUK).count()

                    yedi_gun_once = datetime.now() - timedelta(days=7)
                    son_7_gun = q.filter(Zafiyet.bulunan_tarih >= yedi_gun_once).count()

                    await manager.broadcast({
                        "type": "new_vulnerability",
                        "data": {
                            "toplam": current_count,
                            "kritik": kritik,
                            "yuksek": yuksek,
                            "orta": orta,
                            "dusuk": dusuk,
                            "son_7_gun": son_7_gun,
                            "new_count": current_count - last_count,
                            "latest": {
                                "id": latest.id,
                                "baslik": (latest.baslik or "")[:80],
                                "onem": latest.onem_derecesi.value if latest.onem_derecesi else "Bilinmiyor",
                                "kaynak": latest.kaynak,
                                "tarih": latest.bulunan_tarih.isoformat() if latest.bulunan_tarih else None
                            }
                        }
                    })

                    last_count = current_count
                    last_id = latest.id

        except Exception as e:
            print(f" Monitoring hatası: {e}")
            await asyncio.sleep(10)
        finally:
            if "db" in locals() and db:
                db.close()


@app.post("/api/abone-ekle")
async def abone_ekle(abone: AboneEkleModel):
    db = session_al()
    try:
        mevcut = db.query(Abone).filter(Abone.email == abone.email).first()
        if mevcut:
            if not mevcut.aktif:
                mevcut.aktif = True
                db.commit()
                return {"mesaj": "Abonelik yeniden aktifleştirildi!", "email": abone.email}
            return {"mesaj": "Bu email zaten kayıtlı!", "email": abone.email}

        yeni_abone = Abone(ad_soyad=abone.ad_soyad, email=abone.email, aktif=True)
        db.add(yeni_abone)
        db.commit()
        return {"mesaj": "Abonelik oluşturuldu!", "email": abone.email}
    except Exception as e:
        db.rollback()
        return {"hata": str(e)}
    finally:
        db.close()


@app.delete("/api/abone-sil/{email}")
async def abone_sil(email: str):
    db = session_al()
    try:
        abone = db.query(Abone).filter(Abone.email == email).first()
        if not abone:
            return {"hata": "Abone bulunamadı"}
        abone.aktif = False
        db.commit()
        return {"mesaj": "Abonelik iptal edildi"}
    finally:
        db.close()


@app.get("/api/aboneler")
async def aboneleri_listele():
    db = session_al()
    try:
        aboneler = db.query(Abone).filter(Abone.aktif == True).all()
        return {
            "toplam": len(aboneler),
            "aboneler": [
                {
                    "id": a.id,
                    "ad_soyad": a.ad_soyad,
                    "email": a.email,
                    "kayit_tarihi": a.kayit_tarihi.strftime("%d.%m.%Y") if a.kayit_tarihi else "-"
                }
                for a in aboneler
            ]
        }
    finally:
        db.close()


@app.post("/api/rapor-test")
async def rapor_test_gonder():
    try:
        gonderici = MailGonderici()
        sonuc = gonderici.haftalik_rapor_gonder()
        return {"mesaj": "Test raporu gönderildi!", "sonuc": sonuc}
    except Exception as e:
        return {"hata": str(e)}


@app.get("/api/raporlar")
async def raporlari_listele():
    raporlar = []
    for p in Path(REPORTS_DIR).glob("*.html"):
        stat = p.stat()
        raporlar.append({
            "dosya_adi": p.name,
            "olusturma_tarihi": datetime.fromtimestamp(stat.st_mtime).strftime("%d.%m.%Y %H:%M"),
            "olusturma_ts": stat.st_mtime,
            "url": f"/raporlar/dosya/{p.name}"
        })

    raporlar.sort(key=lambda x: x["olusturma_ts"], reverse=True)
    for r in raporlar:
        r.pop("olusturma_ts", None)

    return {"raporlar": raporlar}


@app.post("/api/rapor-olustur")
async def rapor_olustur():
    olusturucu = RaporOlusturucu()
    rapor = olusturucu.html_rapor_olustur()

    dosya_adi = f"haftalik_rapor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    dosya_yolu = os.path.join(REPORTS_DIR, dosya_adi)

    with open(dosya_yolu, "w", encoding="utf-8") as f:
        f.write(rapor["html"])

    return {"mesaj": "Rapor oluşturuldu", "dosya_adi": dosya_adi, "url": f"/raporlar/dosya/{dosya_adi}"}


@app.get("/raporlar/dosya/{dosya_adi}")
async def rapor_dosya_goster(dosya_adi: str):
    dosya_yolu = _guvenli_rapor_yolu(dosya_adi)
    if not dosya_yolu or not os.path.exists(dosya_yolu):
        return HTMLResponse("<h1>Rapor bulunamadı</h1>", status_code=404)
    return FileResponse(dosya_yolu, media_type="text/html")


@app.post("/api/rapor-gonder")
async def rapor_gonder(payload: RaporGonderModel):
    dosya_yolu = _guvenli_rapor_yolu(payload.dosya_adi)
    if not dosya_yolu or not os.path.exists(dosya_yolu):
        return {"hata": "Rapor bulunamadı"}

    with open(dosya_yolu, "r", encoding="utf-8") as f:
        html_icerik = f.read()

    gonderici = MailGonderici()
    konu = payload.konu or f" Haftalık Zafiyet Raporu | {payload.dosya_adi}"
    sonuc = gonderici.toplu_html_gonder(konu, html_icerik)
    return sonuc


# ============= DEPENDENCY API ENDPOINTS =============

@app.get("/api/dependencies")
async def get_dependencies(limit: int = 50, min_severity: str | None = None):
    """
    Tüm dependency'leri listele
    
    Query Parameters:
    - limit: Maksimum sonuç sayısı (default: 50)
    - min_severity: Minimum önem seviyesi (KRITIK, YUKSEK, ORTA, DUSUK, BILGI)
    
    Response: JSON array of dependencies with CVE info
    """
    db = session_al()
    try:
        all_deps = aggregate_dependencies(db)
        
        # Önem seviyesine göre filtrele
        severity_order = {
            'KRITIK': 5, 'Kritik': 5,
            'YUKSEK': 4, 'Yüksek': 4,
            'ORTA': 3, 'Orta': 3,
            'DUSUK': 2, 'Düşük': 2,
            'BILGI': 1, 'Bilgi': 1
        }
        min_severity_rank = severity_order.get(min_severity or '', 0)
        
        # Sıralama: Zafiyet sayısına göre
        sorted_deps = sorted(
            all_deps.values(),
            key=lambda x: (-x['adet'], x['ad'])
        )[:limit]
        
        filtered_deps = []
        for dep in sorted_deps:
            # Önem seviyesine göre filtrele
            if min_severity and dep['max_severity']:
                severity_str = dep['max_severity'].value if hasattr(dep['max_severity'], 'value') else str(dep['max_severity'])
                severity_rank = severity_order.get(severity_str, 0)
                if severity_rank < min_severity_rank:
                    continue
            
            filtered_deps.append({
                'ad': dep['ad'],
                'version': dep['version'],
                'tur': dep['tur'],
                'adet': dep['adet'],
                'max_severity': dep['max_severity'].value if dep['max_severity'] and hasattr(dep['max_severity'], 'value') else str(dep['max_severity']) if dep['max_severity'] else None,
                'cve_list': sorted(list(dep['cve_list'])) if dep['cve_list'] else []
            })
        
        return {
            'toplam': len(filtered_deps),
            'kaynaklar': {
                'npm': len([d for d in filtered_deps if d['tur'] == 'npm']),
                'python': len([d for d in filtered_deps if d['tur'] == 'python']),
                'java': len([d for d in filtered_deps if d['tur'] == 'java']),
                'ruby': len([d for d in filtered_deps if d['tur'] == 'ruby']),
                'php': len([d for d in filtered_deps if d['tur'] == 'php']),
                'dotnet': len([d for d in filtered_deps if d['tur'] == 'dotnet']),
            },
            'dependencies': filtered_deps,
            'son_guncelleme': datetime.now().isoformat()
        }
    finally:
        db.close()


@app.get("/api/dependencies/{package_name}")
async def get_dependency_details(package_name: str):
    """
    Belirli bir dependency'nin detay bilgisini döndür
    
    Path Parameters:
    - package_name: Paket adı (örn: axios, django, spring-core)
    
    Response: Detaylı bilgi ve ilişkili zafiyetler
    """
    db = session_al()
    try:
        all_deps = aggregate_dependencies(db)
        
        # Paketi bul (case-insensitive)
        found_dep = None
        found_key = None
        for key, dep in all_deps.items():
            if dep['ad'].lower() == package_name.lower():
                found_dep = dep
                found_key = key
                break
        
        if not found_dep:
            return {"hata": f"Paket bulunamadı: {package_name}"}
        
        # İlişkili zafiyetleri getir
        related_zafiyetler = db.query(Zafiyet).filter(
            Zafiyet.id.in_(found_dep['zafiyetler_ids'])
        ).all()
        
        zafiyet_ozet = []
        for z in related_zafiyetler:
            zafiyet_ozet.append({
                'id': z.id,
                'baslik': z.baslik[:100],
                'kaynak': z.kaynak,
                'onem': str(z.onem_derecesi.value) if z.onem_derecesi else 'Bilinmiyor',
                'kategori': z.kategori,
                'cve': cve_numarasi_bul(z),
                'url': z.url
            })
        
        return {
            'ad': found_dep['ad'],
            'version': found_dep['version'],
            'tur': found_dep['tur'],
            'toplam_zafiyetler': found_dep['adet'],
            'max_severity': found_dep['max_severity'].value if found_dep['max_severity'] and hasattr(found_dep['max_severity'], 'value') else str(found_dep['max_severity']) if found_dep['max_severity'] else None,
            'cve_list': sorted(list(found_dep['cve_list'])) if found_dep['cve_list'] else [],
            'zafiyetler': zafiyet_ozet,
            'son_guncelleme': datetime.now().isoformat()
        }
    finally:
        db.close()


@app.get("/api/dependencies-by-type")
async def get_dependencies_by_type(type_filter: str = 'npm'):
    """
    Türe göre dependency'leri listele
    
    Query Parameters:
    - type_filter: npm, python, java, ruby, php, dotnet
    
    Response: Türe ait tüm dependency'ler
    """
    db = session_al()
    try:
        all_deps = aggregate_dependencies(db)
        
        # Türe göre filtrele
        type_deps = [
            {
                'ad': dep['ad'],
                'version': dep['version'],
                'adet': dep['adet'],
                'max_severity': dep['max_severity'].value if dep['max_severity'] and hasattr(dep['max_severity'], 'value') else str(dep['max_severity']) if dep['max_severity'] else None,
                'cve_list': sorted(list(dep['cve_list'])) if dep['cve_list'] else []
            }
            for dep in all_deps.values()
            if dep['tur'] == type_filter
        ]
        
        # Zafiyet sayısına göre sırala
        type_deps.sort(key=lambda x: -x['adet'])
        
        return {
            'tur': type_filter,
            'toplam': len(type_deps),
            'dependencies': type_deps,
            'son_guncelleme': datetime.now().isoformat()
        }
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)