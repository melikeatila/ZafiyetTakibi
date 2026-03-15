from sqlalchemy import Column, Integer, String, Text, DateTime, Enum
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

Base=declarative_base()

class OnemDerecesi(enum.Enum):
    BILGI = "Bilgi"
    DUSUK = "Düşük"
    ORTA = "Orta"
    YUKSEK = "Yüksek"
    KRITIK = "Kritik"


class ZafiyetDurumu(enum.Enum):
    YENI = "Yeni"
    INCELENIYOR = "İnceleniyor"
    DOGRULANDI = "Doğrulandı"
    YANLIS_ALARM = "Yanlış Alarm"

class Zafiyet(Base):
    __tablename__ = "zafiyetler"

    id = Column(Integer, primary_key=True, autoincrement=True)
    baslik = Column(String(500), nullable=False)
    aciklama = Column(Text, nullable=False)
    kaynak = Column(String(50), nullable=False)  
    url = Column(String(1000), nullable=False)
    bulunan_tarih = Column(DateTime, default=datetime.utcnow)
    onem_derecesi = Column(Enum(OnemDerecesi), nullable=True)
    durum = Column(Enum(ZafiyetDurumu), default=ZafiyetDurumu.YENI)
    cve_numarasi = Column(String(50), nullable=True)
    etkilenen_yazilimlar = Column(Text, nullable=True)  
    kategori = Column(String(200), nullable=True)
    
    def __repr__(self):
        return f"<Zafiyet(id={self.id}, baslik='{self.baslik}', kaynak='{self.kaynak}')>"
    
    def to_dict(self):
        return {
            "id": self.id,
            "baslik": self.baslik,
            "aciklama": self.aciklama,
            "kaynak": self.kaynak,
            "url": self.url,
            "bulunan_tarih": self.bulunan_tarih.isoformat(),
            "onem_derecesi": self.onem_derecesi.value if self.onem_derecesi else None,
            "durum": self.durum.value,
            "cve_numarasi": self.cve_numarasi,
            "etkilenen_yazilimlar": self.etkilenen_yazilimlar,
            "kategori": self.kategori
        }