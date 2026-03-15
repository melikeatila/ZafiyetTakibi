import os
import sys
import time
import asyncio
import threading
from datetime import datetime

import schedule
from dotenv import load_dotenv
from sqlalchemy import func

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from toplayicilar.github_toplayici import GithubToplayici
from toplayicilar.telegram_toplayici import TelegramToplayici
from yapay_zeka.analiz import ZafiyetAnalizci
from raporlama.mail_gonder import MailGonderici
from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet

load_dotenv()
JOB_LOCK = threading.Lock()


def log_yazdir(mesaj: str):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {mesaj}")


def env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)).strip())
    except Exception:
        return default


def env_str(key: str, default: str) -> str:
    v = os.getenv(key)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


SETTINGS = {
    "collect_interval_minutes": env_int("COLLECT_INTERVAL_MINUTES", 60),
    "ai_analyze_interval_minutes": env_int("AI_ANALYZE_INTERVAL_MINUTES", 30),
    "ai_batch_size": env_int("AI_BATCH_SIZE", 50),
    "ai_batches_per_run": env_int("AI_BATCHES_PER_RUN", 3),
    "ai_analiz_max_limit": env_int("AI_ANALIZ_MAX_LIMIT", 50),
    "github_lookback_hours": env_int("GITHUB_LOOKBACK_HOURS", 1),
    "telegram_lookback_hours": env_int("TELEGRAM_LOOKBACK_HOURS", 1),
    "run_on_startup": env_str("RUN_ON_STARTUP", "true").lower() == "true",
    "weekly_report_day": env_str("WEEKLY_REPORT_DAY", "friday").lower(),
    "weekly_report_time": env_str("WEEKLY_REPORT_TIME", "09:00"),
}


def _guarded(job_name, fn, *args, **kwargs):
    if not JOB_LOCK.acquire(blocking=False):
        log_yazdir(f" {job_name} atlandı (başka job çalışıyor).")
        return None
    try:
        log_yazdir(f" {job_name} başladı")
        return fn(*args, **kwargs)
    except Exception as e:
        log_yazdir(f" {job_name} hatası: {e}")
        return None
    finally:
        log_yazdir(f" {job_name} bitti")
        JOB_LOCK.release()


def bekleyen_analiz_sayisi():
    db = session_al()
    try:
        return db.query(func.count(Zafiyet.id)).filter(Zafiyet.onem_derecesi.is_(None)).scalar() or 0
    finally:
        db.close()


def ai_analiz_yap(limit=50):
    analizci = ZafiyetAnalizci()

    aday_metotlar = [
        "bekleyenleri_analiz_et",
        "bekleyen_zafiyetleri_analiz_et",
        "bekleyen_kayitlari_analiz_et",
        "toplu_analiz_yap",
        "zafiyetleri_analiz_et",
        "analiz_et",
        "veritabanindaki_zafyetleri_analiz_et",
        "veritabanindaki_zafiyetleri_analiz_et",
    ]

    for metot_adi in aday_metotlar:
        if hasattr(analizci, metot_adi):
            metot = getattr(analizci, metot_adi)
            try:
                return metot(limit=limit)
            except TypeError:
                try:
                    return metot()
                except TypeError:
                    continue

    mevcut_metotlar = [m for m in dir(analizci) if not m.startswith("_")]
    raise AttributeError(
        f"ZafiyetAnalizci içinde uygun analiz metodu bulunamadı. "
        f"Bulunan metotlar: {', '.join(mevcut_metotlar)}"
    )


def bekleyen_analizleri_isle():
    toplam_islenen = 0
    batch_size = SETTINGS["ai_batch_size"]
    max_batch = SETTINGS["ai_batches_per_run"]

    for _ in range(max_batch):
        bekleyen = bekleyen_analiz_sayisi()
        if bekleyen <= 0:
            break

        islenen = ai_analiz_yap(limit=batch_size)
        try:
            islenen_int = int(islenen or 0)
        except Exception:
            islenen_int = 0

        toplam_islenen += islenen_int
        if islenen_int <= 0:
            break

    log_yazdir(f" AI analiz tamamlandı. İşlenen: {toplam_islenen}, Bekleyen: {bekleyen_analiz_sayisi()}")
    return toplam_islenen


def _telegram_sync_topla(saat: int):
    async def _run():
        t = TelegramToplayici()
        await t.baglan()
        try:
            veriler = await t.son_mesajlari_al(saat=saat)
        finally:
            await t.kapat()
        return t, veriler

    return asyncio.run(_run())


def veri_topla():
    log_yazdir(" Veri toplama başladı...")
    toplam_yeni = 0

    try:
        gh = GithubToplayici()
        gh_veriler = gh.tum_verileri_topla(saat=SETTINGS["github_lookback_hours"])
        gh_yeni = gh.veritabanina_kaydet(gh_veriler)
        toplam_yeni += gh_yeni
        log_yazdir(f" GitHub yeni kayıt: {gh_yeni}")
    except Exception as e:
        log_yazdir(f" GitHub toplama hatası: {e}")

    try:
        t, tg_veriler = _telegram_sync_topla(SETTINGS["telegram_lookback_hours"])
        tg_yeni = t.veritabanina_kaydet(tg_veriler)
        toplam_yeni += tg_yeni
        log_yazdir(f" Telegram yeni kayıt: {tg_yeni}")
    except Exception as e:
        log_yazdir(f" Telegram toplama hatası: {e}")

    log_yazdir(f" Veri toplama tamamlandı. Toplam yeni: {toplam_yeni}")

    if toplam_yeni > 0 or bekleyen_analiz_sayisi() > 0:
        log_yazdir(" Bekleyen kayıtlar için anlık AI analizi başlatılıyor...")
        bekleyen_analizleri_isle()

    return toplam_yeni


def haftalik_rapor_gonder():
    try:
        g = MailGonderici()
        sonuc = g.haftalik_rapor_gonder()
        log_yazdir(f" Haftalık rapor gönderildi: {sonuc}")
    except Exception as e:
        log_yazdir(f" Haftalık rapor hatası: {e}")


def ana_dongu():
    log_yazdir(" Worker başlatıldı")

    schedule.every(SETTINGS["collect_interval_minutes"]).minutes.do(
        lambda: _guarded("veri_topla", veri_topla)
    )

    schedule.every(SETTINGS["ai_analyze_interval_minutes"]).minutes.do(
        lambda: _guarded("bekleyen_analizleri_isle", bekleyen_analizleri_isle)
    )

    day = SETTINGS["weekly_report_day"]
    report_time = SETTINGS["weekly_report_time"]
    if day in ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"):
        getattr(schedule.every(), day).at(report_time).do(
            lambda: _guarded("haftalik_rapor_gonder", haftalik_rapor_gonder)
        )

    try:
        if SETTINGS["run_on_startup"]:
            _guarded("startup_veri_topla", veri_topla)

        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        log_yazdir(" Worker durduruldu.")


if __name__ == "__main__":
    ana_dongu()