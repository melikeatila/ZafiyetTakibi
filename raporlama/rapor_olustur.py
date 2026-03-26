import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from datetime import datetime, timedelta
from sqlalchemy import func
from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet, OnemDerecesi
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

class RaporOlusturucu:
    def __init__(self):
        self.client = OpenAI(
            api_key=os.getenv('DEEPSEEK_API_KEY'),
            base_url="https://api.deepseek.com"
        )

    def haftalik_veri_cek(self):
        """Son 7 günün verilerini çek"""
        db = session_al()
        try:
            yedi_gun_once = datetime.now() - timedelta(days=7)

            toplam = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi.isnot(None)
            ).count()

            kritik = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi == OnemDerecesi.KRITIK
            ).count()

            yuksek = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi == OnemDerecesi.YUKSEK
            ).count()

            orta = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi == OnemDerecesi.ORTA
            ).count()

            dusuk = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi == OnemDerecesi.DUSUK
            ).count()

            trend_rows = db.query(
                Zafiyet.baslik,
                Zafiyet.kategori,
                Zafiyet.etkilenen_yazilimlar,
                Zafiyet.onem_derecesi,
                Zafiyet.url,
                func.count(Zafiyet.id).label('adet'),
                func.max(Zafiyet.bulunan_tarih).label('son_tarih')
            ).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi.isnot(None)
            ).group_by(
                Zafiyet.baslik,
                Zafiyet.kategori,
                Zafiyet.etkilenen_yazilimlar,
                Zafiyet.onem_derecesi,
                Zafiyet.url
            ).order_by(
                func.count(Zafiyet.id).desc()
            ).limit(10).all()

            kategori_rows = db.query(
                Zafiyet.kategori,
                func.count(Zafiyet.id).label('adet')
            ).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi.isnot(None),
                Zafiyet.kategori.isnot(None)
            ).group_by(
                Zafiyet.kategori
            ).order_by(
                func.count(Zafiyet.id).desc()
            ).limit(5).all()

            kritik_rows = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi == OnemDerecesi.KRITIK
            ).order_by(Zafiyet.bulunan_tarih.desc()).limit(5).all()

          
            trend_zafiyetler = [
                {
                    'baslik': r.baslik or '',
                    'kategori': r.kategori or 'Belirsiz',
                    'etkilenen_yazilimlar': r.etkilenen_yazilimlar or 'Bilinmiyor',
                    'onem_derecesi_value': r.onem_derecesi.value if r.onem_derecesi else 'Bilinmiyor',
                    'onem_derecesi_key': r.onem_derecesi.name.lower() if r.onem_derecesi else 'bilinmiyor',
                    'url': r.url or '#',
                    'adet': r.adet,
                    'son_tarih': r.son_tarih.strftime('%d.%m.%Y') if r.son_tarih else '-'
                }
                for r in trend_rows
            ]

            kategoriler = [
                {
                    'kategori': r.kategori,
                    'adet': r.adet
                }
                for r in kategori_rows
            ]

            kritik_liste = [
                {
                    'baslik': z.baslik or '',
                    'url': z.url or '#',
                    'etkilenen_yazilimlar': z.etkilenen_yazilimlar or '',
                    'bulunan_tarih': z.bulunan_tarih.strftime('%d.%m.%Y') if z.bulunan_tarih else '-'
                }
                for z in kritik_rows
            ]

            return {
                'toplam': toplam,
                'kritik': kritik,
                'yuksek': yuksek,
                'orta': orta,
                'dusuk': dusuk,
                'trend_zafiyetler': trend_zafiyetler,
                'kategoriler': kategoriler,
                'kritik_liste': kritik_liste,
                'baslangic': yedi_gun_once,
                'bitis': datetime.now()
            }
        finally:
            db.close()

    def ai_ozet_uret(self, veri: dict) -> str:
        try:
            trend_metni = ""
            for i, t in enumerate(veri['trend_zafiyetler'][:5], 1):
                trend_metni += f"{i}. {t['baslik'][:80]} ({t['onem_derecesi_value']}) - {t['adet']} kez\n"  # 

            kategori_metni = ""
            for k in veri['kategoriler']:
                kategori_metni += f"- {k['kategori']}: {k['adet']} adet\n"  


            prompt = f"""Aşağıdaki haftalık siber güvenlik zafiyet verilerini analiz et ve Türkçe profesyonel bir özet yaz.

HAFTALIK İSTATİSTİKLER:
- Toplam Zafiyet: {veri['toplam']}
- Kritik: {veri['kritik']}
- Yüksek: {veri['yuksek']}
- Orta: {veri['orta']}
- Düşük: {veri['dusuk']}

EN ÇOK KONUŞULAN ZAFİYETLER:
{trend_metni}

KATEGORİ DAĞILIMI:
{kategori_metni}

Lütfen şunları içeren 3-4 paragraflık bir özet yaz:
1. Bu haftanın genel güvenlik durumu
2. En dikkat çekici zafiyetler ve neden önemli oldukları
3. En sık görülen zafiyet kategorileri hakkında yorum
4. Güvenlik ekiplerine kısa öneriler

Profesyonel, net ve anlaşılır bir dil kullan."""

            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "Sen deneyimli bir siber güvenlik uzmanısın."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=800
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            print(f" AI özet hatası: {e}")
            return "Bu hafta otomatik özet oluşturulamadı."

    def html_rapor_olustur(self) -> dict:
        """HTML formatında haftalık rapor oluştur"""
        veri = self.haftalik_veri_cek()
        ai_ozet = self.ai_ozet_uret(veri)

        baslangic_str = veri['baslangic'].strftime('%d.%m.%Y')
        bitis_str = veri['bitis'].strftime('%d.%m.%Y')

       
        trend_html = ""
        for t in veri['trend_zafiyetler']:
            renk = {
                'kritik': '#dc2626',
                'yuksek': '#ea580c',
                'orta': '#f59e0b',
                'dusuk': '#10b981',
                'bilgi': '#6b7280'
            }.get(t['onem_derecesi_key'], '#6b7280')

            baslik = t['baslik']
            trend_html += f"""
            <tr>
                <td style="padding:12px; border-bottom:1px solid #2a2a4e;">
                    <a href="{t['url']}" style="color:#00d4ff; text-decoration:none;">
                        {baslik[:80]}{'...' if len(baslik) > 80 else ''}
                    </a>
                </td>
                <td style="padding:12px; border-bottom:1px solid #2a2a4e; text-align:center;">
                    <span style="background:{renk}; color:white; padding:4px 10px; border-radius:12px; font-size:12px; font-weight:600;">
                        {t['onem_derecesi_value']}
                    </span>
                </td>
                <td style="padding:12px; border-bottom:1px solid #2a2a4e; color:#888; font-size:13px;">
                    {t['etkilenen_yazilimlar'][:40]}
                </td>
                <td style="padding:12px; border-bottom:1px solid #2a2a4e; text-align:center; color:#00d4ff; font-weight:700;">
                    {t['adet']}x
                </td>
                <td style="padding:12px; border-bottom:1px solid #2a2a4e; color:#888; font-size:13px;">
                    {t['son_tarih']}
                </td>
            </tr>"""

        kategori_html = ""
        for k in veri['kategoriler']:
            kategori_html += f"""
            <div style="display:flex; justify-content:space-between; align-items:center;
                        padding:10px 15px; background:#252540; border-radius:8px; margin-bottom:8px;">
                <span style="color:#e0e0e0; font-weight:500;">{k['kategori']}</span>
                <span style="background:#00d4ff; color:#0f0f1e; padding:4px 14px;
                             border-radius:20px; font-weight:700; font-size:13px;">{k['adet']}</span>
            </div>""" 

        kritik_html = ""
        for z in veri['kritik_liste']:
            baslik = z['baslik']
            kritik_html += f"""
            <div style="border-left:4px solid #dc2626; padding:12px 15px;
                        background:#1a0a0a; border-radius:0 8px 8px 0; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <a href="{z['url']}" style="color:#ff6b6b; text-decoration:none;
                               font-weight:600; font-size:14px; flex:1;">
                        {baslik[:100]}{'...' if len(baslik) > 100 else ''}
                    </a>
                    <span style="color:#888; font-size:12px; margin-left:10px; white-space:nowrap;">
                        {z['bulunan_tarih']}
                    </span>
                </div>
                {f'<div style="color:#888; font-size:12px; margin-top:5px;">💻 {z["etkilenen_yazilimlar"][:50]}</div>' if z['etkilenen_yazilimlar'] else ''}
            </div>"""

        
        ozet_html = ""
        for paragraf in ai_ozet.split('\n\n'):
            if paragraf.strip():
                ozet_html += f'<p style="margin-bottom:15px; line-height:1.7;">{paragraf.strip()}</p>'  # ✅ EKLENDİ

      
        if veri['kritik_liste']:
            kritik_bolum = f"""
        <div style="background:#1a1a2e; border:1px solid #dc2626; border-radius:12px;
                    padding:25px; margin-bottom:30px;">
            <h2 style="color:#dc2626; margin:0 0 20px; font-size:1.2rem;">
                 Bu Haftanın Kritik Zafiyetleri
            </h2>
            {kritik_html}
        </div>"""
        else:
            kritik_bolum = "" 

        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Haftalık Zafiyet Raporu</title>
</head>
<body style="margin:0; padding:0; background:#0f0f1e; font-family:'Segoe UI',Arial,sans-serif; color:#e0e0e0;">

    <div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
                border-bottom:3px solid #00d4ff; padding:40px 20px; text-align:center;">
        <h1 style="color:#00d4ff; font-size:2rem; margin:0 0 10px;">
             Haftalık Zafiyet Raporu
        </h1>
        <p style="color:#888; margin:0; font-size:1rem;">
            {baslangic_str} — {bitis_str}
        </p>
    </div>

    <div style="max-width:700px; margin:0 auto; padding:30px 20px;">

        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:30px;">
            <tr>
                <td style="padding:5px;">
                    <div style="background:#1a1a2e; border:2px solid #dc2626; border-radius:12px; padding:20px; text-align:center;">
                        <div style="font-size:2.2rem; font-weight:700; color:#dc2626;">{veri['kritik']}</div>
                        <div style="color:#888; font-size:0.85rem; text-transform:uppercase; margin-top:5px;">Kritik</div>
                    </div>
                </td>
                <td style="padding:5px;">
                    <div style="background:#1a1a2e; border:2px solid #ea580c; border-radius:12px; padding:20px; text-align:center;">
                        <div style="font-size:2.2rem; font-weight:700; color:#ea580c;">{veri['yuksek']}</div>
                        <div style="color:#888; font-size:0.85rem; text-transform:uppercase; margin-top:5px;">Yüksek</div>
                    </div>
                </td>
                <td style="padding:5px;">
                    <div style="background:#1a1a2e; border:2px solid #f59e0b; border-radius:12px; padding:20px; text-align:center;">
                        <div style="font-size:2.2rem; font-weight:700; color:#f59e0b;">{veri['orta']}</div>
                        <div style="color:#888; font-size:0.85rem; text-transform:uppercase; margin-top:5px;">Orta</div>
                    </div>
                </td>
                <td style="padding:5px;">
                    <div style="background:#1a1a2e; border:2px solid #10b981; border-radius:12px; padding:20px; text-align:center;">
                        <div style="font-size:2.2rem; font-weight:700; color:#10b981;">{veri['dusuk']}</div>
                        <div style="color:#888; font-size:0.85rem; text-transform:uppercase; margin-top:5px;">Düşük</div>
                    </div>
                </td>
                <td style="padding:5px;">
                    <div style="background:#1a1a2e; border:2px solid #00d4ff; border-radius:12px; padding:20px; text-align:center;">
                        <div style="font-size:2.2rem; font-weight:700; color:#00d4ff;">{veri['toplam']}</div>
                        <div style="color:#888; font-size:0.85rem; text-transform:uppercase; margin-top:5px;">Toplam</div>
                    </div>
                </td>
            </tr>
        </table>

        <div style="background:#1a1a2e; border:1px solid #2a2a4e; border-left:4px solid #00d4ff;
                    border-radius:12px; padding:25px; margin-bottom:30px;">
            <h2 style="color:#00d4ff; margin:0 0 20px; font-size:1.2rem;">
                 Haftalık Değerlendirme
            </h2>
            <div style="color:#ccc; font-size:0.95rem;">
                {ozet_html}
            </div>
        </div>

        <div style="background:#1a1a2e; border:1px solid #2a2a4e; border-radius:12px;
                    padding:25px; margin-bottom:30px;">
            <h2 style="color:#00d4ff; margin:0 0 20px; font-size:1.2rem;">
                 AI analizi sonucu Haftanın Top 10 Zafiyetleri
            </h2>
            <table width="100%" cellpadding="0" cellspacing="0">
                <thead>
                    <tr style="background:#252540;">
                        <th style="padding:10px 12px; text-align:left; color:#888; font-size:12px; text-transform:uppercase;">Başlık</th>
                        <th style="padding:10px 12px; text-align:center; color:#888; font-size:12px; text-transform:uppercase;">Önem</th>
                        <th style="padding:10px 12px; text-align:left; color:#888; font-size:12px; text-transform:uppercase;">Yazılım</th>
                        <th style="padding:10px 12px; text-align:center; color:#888; font-size:12px; text-transform:uppercase;">Tekrar</th>
                        <th style="padding:10px 12px; text-align:left; color:#888; font-size:12px; text-transform:uppercase;">Tarih</th>
                    </tr>
                </thead>
                <tbody>
                    {trend_html}
                </tbody>
            </table>
        </div>

        <div style="background:#1a1a2e; border:1px solid #2a2a4e; border-radius:12px;
                    padding:25px; margin-bottom:30px;">
            <h2 style="color:#00d4ff; margin:0 0 20px; font-size:1.2rem;">
                 Kategori Dağılımı
            </h2>
            {kategori_html}
        </div>

        {kritik_bolum}

        <div style="text-align:center; padding:20px 0; border-top:1px solid #2a2a4e;
                    color:#555; font-size:0.85rem;">
            <p style="margin:0 0 5px;"> Zafiyet Takip Sistemi — Otomatik Haftalık Rapor</p>
            <p style="margin:0;">Bu e-posta otomatik olarak oluşturulmuştur.</p>
        </div>

    </div>
</body>
</html>"""

        return {
            'html': html,
            'veri': veri,
            'baslangic': baslangic_str,
            'bitis': bitis_str
        }


if __name__ == '__main__':
    r = RaporOlusturucu()
    rapor = r.html_rapor_olustur()
    with open('test_rapor.html', 'w', encoding='utf-8') as f:
        f.write(rapor['html'])
    print(" test_rapor.html oluşturuldu!")