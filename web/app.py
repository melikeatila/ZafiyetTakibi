
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

if not os.path.exists(STATIC_DIR):
    raise FileNotFoundError(f" Static klasörü bulunamadı: {STATIC_DIR}")
if not os.path.exists(TEMPLATE_DIR):
    raise FileNotFoundError(f" Template klasörü bulunamadı: {TEMPLATE_DIR}")

app.mount("/statik", StaticFiles(directory=STATIC_DIR), name="statik")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

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

        

        def dengeli_sec(liste, limit=10):
            gh = [z for z in liste if (z.kaynak or "").lower() == "github"][: limit // 2]
            tg = [z for z in liste if (z.kaynak or "").lower() == "telegram"][: limit // 2]
            kalan = limit - (len(gh) + len(tg))
            diger = [z for z in liste if (z.kaynak or "").lower() not in ("github", "telegram")][:kalan]
            secili = gh + tg + diger
            secili.sort(key=lambda z: z.bulunan_tarih or datetime.min, reverse=True)
            return secili[:limit]

        cve_zafiyetler = dengeli_sec(cve_zafiyetler_liste, 10)
        cvesiz_zafiyetler = dengeli_sec(cvesiz_zafiyetler_liste, 10)


        github_sayisi = q.filter(Zafiyet.kaynak == "GitHub").count()
        telegram_sayisi = q.filter(Zafiyet.kaynak == "Telegram").count()

        yedi_gun_once = datetime.now() - timedelta(days=7)

        trend_subquery = q.with_entities(
            Zafiyet.baslik,
            Zafiyet.aciklama,
            Zafiyet.kategori,
            func.count(Zafiyet.id).label("adet"),
            func.max(Zafiyet.kaynak).label("kaynak"),
            func.max(Zafiyet.etkilenen_yazilimlar).label("yazilim"),
            func.max(Zafiyet.onem_derecesi).label("max_onem"),
            func.max(Zafiyet.bulunan_tarih).label("son_tarih"),
            func.max(Zafiyet.url).label("url")
        ).filter(
            and_(
                Zafiyet.baslik.isnot(None),
                Zafiyet.baslik != "",
                Zafiyet.bulunan_tarih >= yedi_gun_once
            )
        ).group_by(
            Zafiyet.baslik, Zafiyet.aciklama, Zafiyet.kategori
        ).order_by(
            func.count(Zafiyet.id).desc()
        ).limit(10).all()

        try:
            analizci = ZafiyetAnalizci()
            ai_kullanilabilir = True
        except Exception as e:
            print(f" AI başlatılamadı: {e}")
            ai_kullanilabilir = False

        trend_zafiyetler = []
        for trend in trend_subquery:
            orijinal_baslik = trend.baslik
            if ai_kullanilabilir:
                try:
                    zafiyet_metni = f"{trend.baslik}\n{trend.aciklama or ''}\nKategori: {trend.kategori or 'Belirsiz'}\nYazılım: {trend.yazilim or '-'}"
                    ai_baslik = analizci.baslik_uret(zafiyet_metni)
                    baslik = ai_baslik if ai_baslik else orijinal_baslik
                except Exception:
                    baslik = orijinal_baslik
            else:
                baslik = orijinal_baslik

            trend_zafiyetler.append({
                "baslik": baslik,
                "orijinal_baslik": orijinal_baslik,
                "kategori": trend.kategori or "Belirsiz",
                "adet": trend.adet,
                "kaynak": trend.kaynak,
                "yazilim": trend.yazilim or "-",
                "max_onem": trend.max_onem.value if trend.max_onem else "Bilinmiyor",
                "son_tarih": trend.son_tarih.strftime("%d.%m.%Y") if trend.son_tarih else "-",
                "url": trend.url
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
            "cve_zafiyetler": cve_zafiyetler,
            "cvesiz_zafiyetler": cvesiz_zafiyetler,
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)