import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet
from sqlalchemy import func, or_

db = session_al()

print("\n" + "="*80)
print(" GELIŞMIŞ DUPLICATE TEMİZLEME")
print("="*80)

# 1. URL bazında duplicate'ler
print("\n URL bazında temizlik...")
url_duplicates = db.query(
    Zafiyet.url,
    func.min(Zafiyet.id).label('keep_id'),
    func.count(Zafiyet.id).label('count')
).filter(
    Zafiyet.url != None,
    Zafiyet.url != ''
).group_by(
    Zafiyet.url
).having(
    func.count(Zafiyet.id) > 1
).all()

print(f"   {len(url_duplicates)} URL'de duplicate bulundu")

total_url_deleted = 0
for url, keep_id, count in url_duplicates:
    to_delete = db.query(Zafiyet).filter(
        Zafiyet.url == url,
        Zafiyet.id != keep_id
    ).all()
    
    for z in to_delete:
        db.delete(z)
        total_url_deleted += 1

if total_url_deleted > 0:
    db.commit()
    print(f"    {total_url_deleted} kayıt silindi")


print("\n CVE bazında temizlik...")
cve_duplicates = db.query(
    Zafiyet.cve_numarasi,
    Zafiyet.kaynak,
    func.min(Zafiyet.id).label('keep_id'),
    func.count(Zafiyet.id).label('count')
).filter(
    Zafiyet.cve_numarasi != None,
    Zafiyet.cve_numarasi != '',
    Zafiyet.cve_numarasi.like('CVE-%')
).group_by(
    Zafiyet.cve_numarasi,
    Zafiyet.kaynak
).having(
    func.count(Zafiyet.id) > 1
).all()

print(f"   {len(cve_duplicates)} CVE'de duplicate bulundu")

total_cve_deleted = 0
for cve, kaynak, keep_id, count in cve_duplicates:
    to_delete = db.query(Zafiyet).filter(
        Zafiyet.cve_numarasi == cve,
        Zafiyet.kaynak == kaynak,
        Zafiyet.id != keep_id
    ).all()
    
    for z in to_delete:
        db.delete(z)
        total_cve_deleted += 1

if total_cve_deleted > 0:
    db.commit()
    print(f"    {total_cve_deleted} kayıt silindi")


print("\n Son durum kontrolü...")

all_concrete = db.query(Zafiyet).filter(
    or_(
        Zafiyet.baslik.ilike('%Concrete CMS%XSS%'),
        Zafiyet.baslik.ilike('%ConcreteCMS%XSS%'),
        Zafiyet.baslik.ilike('%Concrete%Cross-Site Scripting%')
    )
).all()

unique_cves = set()
unique_urls = set()

for z in all_concrete:
    if z.cve_numarasi:
        unique_cves.add(z.cve_numarasi)
    if z.url:
        unique_urls.add(z.url)

print(f"   Toplam kayıt: {len(all_concrete)}")
print(f"   Benzersiz CVE: {len(unique_cves)}")
print(f"   Benzersiz URL: {len(unique_urls)}")

print(f"\n Benzersiz CVE'ler:")
for cve in sorted(unique_cves):
    print(f"   - {cve}")

db.close()

print(f"\n Temizlik tamamlandı!")
print(f"   URL bazında: {total_url_deleted} silindi")
print(f"   CVE bazında: {total_cve_deleted} silindi")
print(f"   Kalan: {len(all_concrete)} kayıt\n")

print("="*80 + "\n")