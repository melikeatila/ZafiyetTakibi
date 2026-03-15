from veritabani.baglanti import baglanti_test, veritabani_olustur

print(" Veritabanı bağlantısı test ediliyor...")
if baglanti_test():
    print("\n Tablolar oluşturuluyor...")
    veritabani_olustur()
    print("\n Kurulum tamamlandı!")
else:
    print("\n Bağlantı başarısız. .env dosyasını kontrol et.")