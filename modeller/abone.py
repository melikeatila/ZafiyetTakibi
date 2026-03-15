from sqlalchemy import Column, Integer, String, Boolean, DateTime
from modeller.zafiyet import Base
from datetime import datetime

class Abone(Base):
    __tablename__ = "aboneler"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ad_soyad = Column(String(100), nullable=False)
    email = Column(String(200), nullable=False, unique=True)
    aktif = Column(Boolean, default=True)
    kayit_tarihi = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Abone(id={self.id}, email='{self.email}')>"