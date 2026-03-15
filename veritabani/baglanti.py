import os
from urllib.parse import quote_plus

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "zafiyet_takibi")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DB_PASSWORD_ENC = quote_plus(DB_PASSWORD)
DB_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD_ENC}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(
    DB_URL,
    echo=False,          
    pool_pre_ping=True,  
    future=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def session_al():
    return SessionLocal()


def veritabanini_hazirla():
    
    from modeller.zafiyet import Zafiyet  
    from modeller.abone import Abone      
    Base.metadata.create_all(bind=engine)


def baglanti_testi():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False