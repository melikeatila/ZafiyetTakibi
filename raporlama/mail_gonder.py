import sys
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from veritabani.baglanti import session_al
from modeller.abone import Abone
from raporlama.rapor_olustur import RaporOlusturucu


load_dotenv()


class MailGonderici:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.smtp_from = os.getenv("SMTP_FROM", self.smtp_user)
        self.gonderen_ad = os.getenv("SMTP_SENDER_NAME", "Zafiyet Takip Sistemi")

        if not self.smtp_user or not self.smtp_password:
            raise ValueError("SMTP_USER ve SMTP_PASSWORD .env içinde tanımlı olmalı.")

    def mail_gonder(self, alici_email: str, alici_ad: str, konu: str, html_icerik: str) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = konu
            msg["From"] = f"{self.gonderen_ad} <{self.smtp_from}>"
            msg["To"] = alici_email
            msg.attach(MIMEText(html_icerik, "html", "utf-8"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_from, alici_email, msg.as_string())

            print(f" Mail gönderildi: {alici_email}")
            return True
        except Exception as e:
            print(f" Mail gönderilemedi ({alici_email}): {e}")
            return False

    def haftalik_rapor_gonder(self) -> dict:
        print("\n" + "=" * 60)
        print("HAFTALIK RAPOR GÖNDERİMİ BAŞLIYOR")
        print("=" * 60)

        try:
            olusturucu = RaporOlusturucu()
            rapor = olusturucu.html_rapor_olustur()
        except Exception as e:
            print(f" Rapor oluşturulamadı: {e}")
            return {"basarili": 0, "basarisiz": 0, "hata": str(e)}

        proje_kok = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        rapor_dir = os.path.join(proje_kok, "raporlar")
        os.makedirs(rapor_dir, exist_ok=True)

        dosya_adi = f"haftalik_rapor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        dosya_yolu = os.path.join(rapor_dir, dosya_adi)
        with open(dosya_yolu, "w", encoding="utf-8") as f:
            f.write(rapor["html"])

        konu = f" Haftalık Zafiyet Raporu | {rapor['baslangic']} - {rapor['bitis']}"

        db = session_al()
        try:
            aboneler = db.query(Abone).filter(Abone.aktif == True).all()
        finally:
            db.close()

        if not aboneler:
            print(" Aktif abone bulunamadı.")
            return {"basarili": 0, "basarisiz": 0, "dosya": dosya_adi, "mesaj": "Aktif abone yok"}

        basarili = 0
        basarisiz = 0

        for abone in aboneler:
            if self.mail_gonder(abone.email, abone.ad_soyad, konu, rapor["html"]):
                basarili += 1
            else:
                basarisiz += 1

        print(f" Başarılı: {basarili} |  Başarısız: {basarisiz}")
        print("=" * 60 + "\n")

        return {"basarili": basarili, "basarisiz": basarisiz, "dosya": dosya_adi}

    def toplu_html_gonder(self, konu: str, html_icerik: str) -> dict:
        db = session_al()
        try:
            aboneler = db.query(Abone).filter(Abone.aktif == True).all()
        finally:
            db.close()

        if not aboneler:
            return {"mesaj": "Aktif abone yok", "basarili": 0, "basarisiz": 0}

        basarili = 0
        basarisiz = 0
        for abone in aboneler:
            if self.mail_gonder(abone.email, abone.ad_soyad, konu, html_icerik):
                basarili += 1
            else:
                basarisiz += 1

        return {"mesaj": "Gönderim tamamlandı", "basarili": basarili, "basarisiz": basarisiz}


if __name__ == "__main__":
    gonderici = MailGonderici()
    print(gonderici.haftalik_rapor_gonder())