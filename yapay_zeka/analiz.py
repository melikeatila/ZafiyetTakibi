import os
import re
import sys
import json
import time
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from openai import OpenAI
from dotenv import load_dotenv
from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet, OnemDerecesi

load_dotenv()


class ZafiyetAnalizci:
    def __init__(self):
        self.api_key = os.getenv('DEEPSEEK_API_KEY')
        if not self.api_key:
            raise ValueError("DEEPSEEK_API_KEY bulunamadi!")
        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://api.deepseek.com"
        )
        print(" DeepSeek API hazir")

    def _temizle(self, metin, limit=500):
        if not metin:
            return ""
        metin = str(metin).replace("\x00", " ").strip()
        return metin[:limit]

    def zafiyet_analiz_et(self, baslik: str, aciklama: str) -> str | None:
        try:
            metin = f"{self._temizle(baslik, 200)}\n{self._temizle(aciklama, 500)}"

            prompt = f"""Aşağıdaki güvenlik açığını analiz et ve SADECE JSON formatında yanıt ver.
Asla markdown, ```json, açıklama veya ek metin yazma.

Zafiyet: {metin}

{{
  "onem_derecesi": "KRITIK|YUKSEK|ORTA|DUSUK|BILGI",
  "kategori": "SQL Injection|XSS|RCE|LFI|CSRF|Buffer Overflow|Privilege Escalation|DoS|Diger",
  "etkilenen_yazilimlar": "kısa ürün adı veya Bilinmiyor"
}}"""

            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {
                        "role": "system",
                        "content": "Yalnızca geçerli JSON döndür. Başka hiçbir şey yazma."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.0,
                max_tokens=200
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            print(f" API hatası: {e}")
            return None

    def _json_parse(self, sonuc: str) -> dict | None:
        if not sonuc:
            return None
        try:
            temiz = sonuc.replace('```json', '').replace('```', '').strip()
            start = temiz.find('{')
            end = temiz.rfind('}') + 1
            if start == -1 or end <= start:
                return None
            return json.loads(temiz[start:end])
        except json.JSONDecodeError:
            return None

    def _onem_enum(self, deger: str) -> OnemDerecesi:
        deger = (deger or "").upper().strip()
        gecerli = ["KRITIK", "YUKSEK", "ORTA", "DUSUK", "BILGI"]
        if deger in gecerli:
            return OnemDerecesi[deger]
        return OnemDerecesi.BILGI
    
    def baslik_uret(self, metin: str, max_uzunluk: int = 95) -> str | None:
        """
        Trend kartı için kullanıcı dostu, tek satır, açıklayıcı başlık üretir.
        Örn: [CVE-2025-68613] n8n commit zincirinde kimlik doğrulama atlatma riski
        """
        if not metin:
            return None

        try:
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", metin, re.IGNORECASE)
            cve = cve_match.group(0).upper() if cve_match else None

            prompt = f"""
Aşağıdaki güvenlik kaydı için son kullanıcıya anlaşılır, kısa ve açıklayıcı TEK SATIR başlık üret.
Kurallar:
- Teknik ama sade Türkçe kullan.
- Ürün/servis adı + zafiyet türü + etki bilgisini ver.
- 95 karakteri geçme.
- Markdown, emoji, tırnak, açıklama ekleme.
- Sadece başlığı döndür.

Kayıt:
{metin}
""".strip()

            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "Sadece tek satır başlık döndür."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=80,
            )
            baslik = (response.choices[0].message.content or "").strip()
            baslik = baslik.replace("\n", " ").replace("```", "").strip(" \"'")

            if not baslik:
                return None

            if cve and cve not in baslik.upper():
                baslik = f"[{cve}] {baslik}"

            if len(baslik) > max_uzunluk:
                baslik = baslik[:max_uzunluk].rsplit(" ", 1)[0] + "…"

            return baslik

        except Exception as e:
            print(f" Başlık üretme hatası: {e}")
            return None

    # ...existing code...

    def veritabanindaki_zafyetleri_analiz_et(self, limit=50):
        db = session_al()
        try:
            print(f"\n{'='*60}")
            print(f" AI ANALİZ BAŞLADI - {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}")

            zafiyetler = (
                db.query(Zafiyet)
                .filter(Zafiyet.onem_derecesi.is_(None))
                .limit(limit)
                .all()
            )

            toplam = len(zafiyetler)
            print(f" Bekleyen kayıt: {toplam}\n")

            if toplam == 0:
                print(" Analiz edilecek kayıt yok.")
                return 0

            basarili = 0
            basarisiz = 0

            for i, zafiyet in enumerate(zafiyetler, 1):
                try:
                    baslik_log = (zafiyet.baslik or "")[:50].encode('ascii', 'ignore').decode('ascii')
                    print(f"[{i}/{toplam}] {baslik_log}...")

                    sonuc = self.zafiyet_analiz_et(
                        zafiyet.baslik or "",
                        zafiyet.aciklama or ""
                    )

                    analiz = self._json_parse(sonuc)

                    if analiz:
                        onem = (analiz.get('onem_derecesi') or 'BILGI').upper()
                        kategori = (analiz.get('kategori') or 'Diger').strip()
                        yazilim = (analiz.get('etkilenen_yazilimlar') or '').strip()

                        zafiyet.onem_derecesi = self._onem_enum(onem)
                        zafiyet.kategori = kategori if kategori else (zafiyet.kategori or "Diger")
                        zafiyet.etkilenen_yazilimlar = (
                            yazilim
                            if yazilim and yazilim.lower() not in ('null', 'bilinmiyor', '')
                            else (zafiyet.etkilenen_yazilimlar or "Bilinmiyor")  
                        )

                        kat_log = kategori.encode('ascii', 'ignore').decode('ascii')
                        print(f"     {onem} | {kat_log}")
                        basarili += 1
                    else:
                        zafiyet.onem_derecesi = OnemDerecesi.BILGI
                        zafiyet.kategori = zafiyet.kategori or "Diger"
                        zafiyet.etkilenen_yazilimlar = zafiyet.etkilenen_yazilimlar or "Bilinmiyor" 
                        print(f"     JSON parse başarısız, BILGI atandı")
                        basarisiz += 1

                    if i % 5 == 0:
                        db.commit()
                        print(f"\n     {i} kayıt DB'ye yazıldı\n")

                    time.sleep(0.3)

                except Exception as kayit_hatasi:
                    hata_log = str(kayit_hatasi)[:80].encode('ascii', 'ignore').decode('ascii')
                    print(f"     ID:{zafiyet.id} atlandı: {hata_log}")
                   
                    try:
                        zafiyet.onem_derecesi = OnemDerecesi.BILGI
                        zafiyet.kategori = zafiyet.kategori or "Diger"
                        zafiyet.etkilenen_yazilimlar = "Bilinmiyor"
                        db.commit()
                    except Exception:
                        db.rollback()
                    basarisiz += 1
                    continue

            db.commit()

            print(f"\n{'='*60}")
            print(f" ANALİZ TAMAMLANDI - {datetime.now().strftime('%H:%M:%S')}")
            print(f"   Başarılı : {basarili}")
            print(f"   Başarısız: {basarisiz}")
            print(f"   Toplam   : {toplam}")
            print(f"{'='*60}\n")

            return basarili + basarisiz

        except Exception as e:
            db.rollback()
            print(f"\n KRİTİK HATA: {e}\n")
            return 0
        finally:
            db.close()


    #
    def bekleyenleri_analiz_et(self, limit=50):
        return self.veritabanindaki_zafyetleri_analiz_et(limit=limit)

    def analiz_et(self, limit=50):
        return self.veritabanindaki_zafyetleri_analiz_et(limit=limit)

    def veritabanindaki_zafiyetleri_analiz_et(self, limit=50):
        return self.veritabanindaki_zafyetleri_analiz_et(limit=limit)


if __name__ == '__main__':
    analizci = ZafiyetAnalizci()
    analizci.veritabanindaki_zafyetleri_analiz_et(limit=50)