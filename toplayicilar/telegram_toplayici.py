import os
import re
import sys
import asyncio
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from telethon import TelegramClient
from telethon.errors import (
    FloodWaitError,
    UsernameInvalidError,
    UsernameNotOccupiedError,
    SessionPasswordNeededError,
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet, ZafiyetDurumu

load_dotenv()

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class TelegramToplayici:
    def __init__(self):
        api_id = os.getenv("TELEGRAM_API_ID")
        api_hash = os.getenv("TELEGRAM_API_HASH")
        self.phone = (os.getenv("TELEGRAM_PHONE") or "").strip()
        self.session_name = os.getenv("TELEGRAM_SESSION_NAME", "zafiyet_session")

        if not api_id or not api_hash:
            raise ValueError("TELEGRAM_API_ID ve TELEGRAM_API_HASH .env içinde tanımlı olmalı.")

        self.client = TelegramClient(self.session_name, int(api_id), api_hash)

        env_channels = os.getenv("TELEGRAM_CHANNELS", "").strip()
        if env_channels:
            self.kanallar = []
            for c in env_channels.split(","):
                kanal = c.strip().strip('"').strip("'")
                if kanal:
                    if not kanal.startswith("@"):
                        kanal = f"@{kanal}"
                    self.kanallar.append(kanal)
        else:
            self.kanallar = ["@thehackernews", "@BleepingComputer", "@cveNotify", "@siberbulten"]

    def _zorunlu_aciklama(self, aciklama, baslik=""):
        temiz = (aciklama or "").strip()
        if temiz:
            return temiz[:2000]

        temiz_baslik = (baslik or "").strip() or "Başlıksız kayıt"
        return f"Açıklama bulunamadı. Başlık: {temiz_baslik}"

    async def baglan(self):
        try:
            await self.client.start(phone=self.phone if self.phone else None)
        except SessionPasswordNeededError:
            raise ValueError("Telegram 2FA şifresi gerekli. Önce manuel oturum açın.")
        except Exception as e:
            raise ValueError(f"Telegram oturumu başlatılamadı: {e}")

        if not await self.client.is_user_authorized():
            raise ValueError("Telegram kullanıcısı authorize değil. Session oluşturulmalı.")

        print(" Telegram'a bağlanıldı ve oturum doğrulandı!")

    async def kapat(self):
        try:
            await self.client.disconnect()
        except Exception:
            pass

    async def son_mesajlari_al(self, saat=1):
        veriler = []
        esik = datetime.now(timezone.utc) - timedelta(hours=saat)

        for kanal in self.kanallar:
            print(f" Kanal taranıyor: {kanal}")
            try:
                entity = await self.client.get_entity(kanal)
            except (UsernameInvalidError, UsernameNotOccupiedError):
                print(f" Kanal bulunamadı/geçersiz: {kanal}")
                continue
            except Exception as e:
                print(f" Kanal erişim hatası ({kanal}): {e}")
                continue

            try:
                async for msg in self.client.iter_messages(entity, limit=300):
                    if not msg or not msg.date:
                        continue

                    msg_tarih = msg.date
                    if msg_tarih.tzinfo is None:
                        msg_tarih = msg_tarih.replace(tzinfo=timezone.utc)

                    if msg_tarih < esik:
                        break

                    icerik = (msg.message or "").strip()
                    if not icerik:
                        continue

                    cve_match = CVE_PATTERN.search(icerik)
                    cve = cve_match.group(0).upper() if cve_match else None

                    satirlar = [s.strip() for s in icerik.splitlines() if s.strip()]
                    baslik = satirlar[0][:300] if satirlar else icerik[:300]
                    aciklama = self._zorunlu_aciklama(icerik, baslik)

                    url = None
                    if getattr(msg, "id", None):
                        kanal_ad = kanal.lstrip("@")
                        url = f"https://t.me/{kanal_ad}/{msg.id}"

                    veri = {
                        "baslik": baslik,
                        "aciklama": aciklama,
                        "kaynak": "Telegram",
                        "url": url if url else f"https://t.me/{kanal.lstrip('@')}",
                        "bulunan_tarih": msg_tarih,
                        "cve_numarasi": cve,
                        "kategori": f"Telegram ({kanal})",
                        "etkilenen_yazilimlar": None,
                    }
                    veriler.append(veri)

            except FloodWaitError as e:
                print(f" FloodWait: {kanal} için {e.seconds}s beklenmeli.")
                continue
            except Exception as e:
                print(f" Mesaj okuma hatası ({kanal}): {e}")
                continue

        return veriler

    def veritabanina_kaydet(self, veriler):
        if not veriler:
            return 0

        db = session_al()
        yeni = 0
        try:
            durum_default = getattr(ZafiyetDurumu, "YENI", None)

            for v in veriler:
                url = (v.get("url") or "").strip()
                baslik = (v.get("baslik") or "").strip()
                aciklama = self._zorunlu_aciklama(v.get("aciklama"), baslik)

                mevcut = None
                if url:
                    mevcut = db.query(Zafiyet).filter(Zafiyet.url == url).first()

                if mevcut is None and baslik:
                    mevcut = db.query(Zafiyet).filter(
                        Zafiyet.kaynak == "Telegram",
                        Zafiyet.baslik == baslik
                    ).first()

                if mevcut:
                    continue

                z = Zafiyet(
                    baslik=baslik or "Başlıksız Telegram Kaydı",
                    aciklama=aciklama,
                    kaynak="Telegram",
                    url=url or None,
                    bulunan_tarih=v.get("bulunan_tarih") or datetime.now(timezone.utc),
                    cve_numarasi=v.get("cve_numarasi"),
                    kategori=v.get("kategori"),
                    etkilenen_yazilimlar=v.get("etkilenen_yazilimlar"),
                    onem_derecesi=None,
                    durum=durum_default,
                )
                db.add(z)
                yeni += 1

            db.commit()
            return yeni
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


async def _test():
    t = TelegramToplayici()
    await t.baglan()
    veriler = await t.son_mesajlari_al(saat=6)
    await t.kapat()
    print(f"Toplam: {len(veriler)} mesaj")
    if veriler:
        print(veriler[0])


if __name__ == "__main__":
    asyncio.run(_test())