from veritabani.baglanti import SessionLocal
from modeller.zafiyet import Zafiyet
from toplayicilar.exploit_db_toplayici import ExploitDBCollector
from toplayicilar.zerotday_toplayici import ZeroDayTodayCollector

def update_urls():
    db = SessionLocal()
    guncellenen = 0
    try:
        # Exploit-DB
        print('Exploit-DB guncelleniyor...')
        edb = ExploitDBCollector()
        edb_veriler = edb.get_latest_from_rss(limit=100)
        for veri in edb_veriler:
            link = veri.get('link') or veri.get('url')
            if link:
                mevcut = db.query(Zafiyet).filter(Zafiyet.kaynak == 'Exploit-DB', Zafiyet.baslik == veri.get('title')).first()
                if mevcut and not mevcut.url:
                    mevcut.url = link
                    guncellenen += 1

        # 0day.today
        print('0day.today guncelleniyor...')
        zday = ZeroDayTodayCollector()
        zday_veriler = zday.get_latest_from_rss(limit=100)
        for veri in zday_veriler:
            link = veri.get('link') or veri.get('url')
            if link:
                mevcut = db.query(Zafiyet).filter(Zafiyet.kaynak == '0day.today', Zafiyet.baslik == veri.get('title')).first()
                if mevcut and not mevcut.url:
                    mevcut.url = link
                    guncellenen += 1
                    
        db.commit()
        print(f'Islem tamam! Toplam guncellenen kayit: {guncellenen}')
    except Exception as e:
        db.rollback()
        print(f'Hata: {e}')
    finally:
        db.close()

if __name__ == '__main__':
    update_urls()
