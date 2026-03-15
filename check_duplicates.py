import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet
from sqlalchemy import func

db = session_al()

print("\n" + "="*80)
print(" DUPLICATE ZAFIYET ANALİZİ")
print("="*80)


concrete_zafiyetler = db.query(Zafiyet).filter(
    Zafiyet.baslik.ilike('%Concrete CMS%XSS%')
).all()

print(f"\n Toplam Concrete CMS XSS zafiyeti: {len(concrete_zafiyetler)}")

if concrete_zafiyetler:
    print("\n Detaylar:")
    print("-" * 80)
    
    for i, z in enumerate(concrete_zafiyetler, 1):
        print(f"\n{i}. ID: {z.id}")
        print(f"   Başlık: {z.baslik[:60]}")
        print(f"   Kaynak: {z.kaynak}")
        print(f"   CVE: {z.cve_numarasi or 'Yok'}")
        print(f"   Tarih: {z.bulunan_tarih.strftime('%d.%m.%Y %H:%M:%S') if z.bulunan_tarih else '-'}")
        print(f"   URL: {z.url[:60] if z.url else '-'}...")


print("\n\n EN ÇOK TEKRAR EDEN ZAFİYETLER:")
print("-" * 80)

duplicates = db.query(
    Zafiyet.baslik,
    func.count(Zafiyet.id).label('tekrar'),
    func.max(Zafiyet.kaynak).label('kaynak')
).group_by(
    Zafiyet.baslik
).having(
    func.count(Zafiyet.id) > 1
).order_by(
    func.count(Zafiyet.id).desc()
).limit(5).all()

for baslik, tekrar, kaynak in duplicates:
    print(f"\n {tekrar}x | {kaynak} | {baslik[:60]}...")


print("\n\n AYNI URL'DEN GELEN DUPLICATE'LER:")
print("-" * 80)

url_duplicates = db.query(
    Zafiyet.url,
    func.count(Zafiyet.id).label('tekrar'),
    func.max(Zafiyet.baslik).label('baslik')
).filter(
    Zafiyet.url != None,
    Zafiyet.url != ''
).group_by(
    Zafiyet.url
).having(
    func.count(Zafiyet.id) > 1
).order_by(
    func.count(Zafiyet.id).desc()
).limit(5).all()

for url, tekrar, baslik in url_duplicates:
    print(f"\n {tekrar}x | {baslik[:60]}...")
    print(f"   URL: {url[:80]}")

db.close()

print("\n" + "="*80 + "\n")