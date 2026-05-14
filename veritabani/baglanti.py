import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from modeller.abone import Abone
from modeller.zafiyet import Zafiyet

load_dotenv()

# SQLite bağlantı ayarları
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "zafiyet_takibi.db")
DATABASE_URL = f"sqlite:///{DB_PATH.replace(chr(92), '/')}"

engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def session_al():
    """SQLAlchemy session açar"""
    return SessionLocal()


def veritabanini_hazirla():
    """Veritabanı tablolarını oluşturur"""
    try:
        Zafiyet.metadata.create_all(bind=engine)
        Abone.metadata.create_all(bind=engine)
        return True
    except Exception as e:
        print(f"Veritabanı hazırlama hatası: {e}")
        return False


def baglanti_testi():
    """Veritabanı bağlantısını test eder"""
    try:
        session = session_al()
        session.execute(text("SELECT 1"))
        session.close()
        return True
    except Exception as e:
        print(f"Bağlantı hatası: {e}")
        return False


# Alias'lar
baglanti_test = baglanti_testi
veritabani_olustur = veritabanini_hazirla
