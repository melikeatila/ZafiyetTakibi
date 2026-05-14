import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from datetime import datetime, timedelta
import re
from sqlalchemy import func
from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet, OnemDerecesi
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

REMOTE_PATTERN = re.compile(
    r"\b(remote|rce|uzaktan|remote code execution|command injection|auth(entication)? bypass)\b",
    re.IGNORECASE,
)

ANLAMSIZ_TREND_ETIKETLERI = {"diger", "bilinmiyor", "unknown", "genel"}
PINLI_TREND_TERIMLERI = ("litellm",)

class RaporOlusturucu:
    def __init__(self):
        self.client = OpenAI(
            api_key=os.getenv('DEEPSEEK_API_KEY'),
            base_url="https://api.deepseek.com"
        )

    def _anahtar_kelime_bul(self, baslik: str) -> str:
        metin = (baslik or "").lower()
        metin = re.sub(r"cve-\d{4}-\d{4,7}", " ", metin, flags=re.IGNORECASE)

        adaylar = re.findall(r"[a-z0-9][a-z0-9+._-]{2,}", metin)
        stop = {
            "vulnerability", "security", "advisory", "update", "patch", "bug",
            "issue", "critical", "high", "medium", "low", "remote", "code",
            "execution", "rce", "xss", "sql", "injection", "disclosure",
            "dos", "bypass", "overflow", "exploit", "auth", "authentication",
            "zafiyet", "guvenlik", "açığı", "acigi", "kritik", "yuksek", "orta", "dusuk",
            "new", "latest", "breaking", "alert", "the", "this", "that", "popular", "malicious"
        }
        for t in adaylar:
            if t.isdigit():
                continue
            if not re.search(r"[a-z]", t):
                continue
            if t not in stop:
                return t
        return "diger"

    def _urun_etiketi_bul(self, zafiyet) -> str:
        yazilim = (zafiyet.etkilenen_yazilimlar or "").strip().lower()
        if yazilim and yazilim not in {"-", "bilinmiyor", "unknown"}:
            aday = re.split(r"[,/|;]", yazilim, maxsplit=1)[0].strip()
            aday = re.sub(r"\s+", " ", aday)
            aday = re.sub(r"\b(v\d+[\w.-]*|\d+[\w.-]*)\b", "", aday).strip()
            if len(aday) >= 3 and re.search(r"[a-z]", aday):
                return aday

        metin = " ".join([
            zafiyet.baslik or "",
            zafiyet.aciklama or "",
            zafiyet.kategori or "",
            zafiyet.url or "",
        ]).lower()

        for terim in PINLI_TREND_TERIMLERI:
            if re.search(rf"\b{re.escape(terim)}\b", metin):
                return terim

        return self._anahtar_kelime_bul(zafiyet.baslik or "")

    def _trend_sirala(self, trend_gruplari: dict, limit: int = 10) -> list:
        sirali = sorted(
            trend_gruplari.values(),
            key=lambda x: (x['adet'], x['son_tarih'] or datetime.min),
            reverse=True,
        )

        anlamli = [
            g for g in sirali
            if (g.get('grup_etiketi') or '').strip().lower() not in ANLAMSIZ_TREND_ETIKETLERI
        ]
        secilen = anlamli[:limit]

        if len(secilen) < limit:
            secili_anahtarlar = {s.get('anahtar') for s in secilen}
            for aday in sirali:
                if len(secilen) >= limit:
                    break
                if aday.get('anahtar') in secili_anahtarlar:
                    continue
                secilen.append(aday)
                secili_anahtarlar.add(aday.get('anahtar'))

        secili_anahtarlar = {s.get('anahtar') for s in secilen}
        for terim in PINLI_TREND_TERIMLERI:
            aday = next(
                (
                    g for g in sirali
                    if terim in (g.get('grup_etiketi') or '').lower()
                    or terim in (g.get('etkilenen_yazilimlar') or '').lower()
                    or terim in (g.get('baslik') or '').lower()
                ),
                None,
            )
            if not aday or aday.get('anahtar') in secili_anahtarlar:
                continue
            if len(secilen) < limit:
                secilen.append(aday)
            else:
                secilen[-1] = aday
            secili_anahtarlar = {s.get('anahtar') for s in secilen}

        return secilen

    def _cve_numarasi_bul(self, zafiyet) -> str | None:
        alanlar = [
            zafiyet.cve_numarasi,
            zafiyet.baslik,
            zafiyet.aciklama,
        ]
        for alan in alanlar:
            if not alan:
                continue
            eslesme = re.search(r"CVE-\d{4}-\d{4,7}", str(alan), re.IGNORECASE)
            if eslesme:
                return eslesme.group(0).upper()
        return None

    def _onem_sira(self, onem) -> int:
        if not onem:
            return 0
        return {
            OnemDerecesi.KRITIK: 4,
            OnemDerecesi.YUKSEK: 3,
            OnemDerecesi.ORTA: 2,
            OnemDerecesi.DUSUK: 1,
            OnemDerecesi.BILGI: 0,
        }.get(onem, 0)

    # --- Dependency extraction (lightweight, local copy of web.app logic) ---
    def _extract_dependencies(self, metin: str) -> list:
        if not metin:
            return []

        import re
        metin_lower = metin.lower()
        deps = []

        npm_pattern = r'\b(axios|express|react|vue|angular|webpack|typescript|lodash|jquery|moment|chalk|jest|mocha|cypress|eslint|prettier|babel|rollup|vite|next|nuxt|nest|fastify|hapi|koa|ejs|handlebars|pug|sass|less|postcss|pm2|forever|nodemon|dotenv|jsonwebtoken|bcrypt|passport|cors|helmet|compression|multer|socket\.io|ws|mqtt|amqp|redis|mongodb|mongoose|sequelize|typeorm|knex|prisma|graphql|apollo|relay|fetch|supertest|sinon|chai|should)\b(?:[\s@=^>~-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][a-z0-9]+)?)?)?'
        for m in re.finditer(npm_pattern, metin_lower):
            name = m.group(1)
            ver = m.group(2) if len(m.groups()) > 1 else None
            deps.append({'ad': name, 'version': ver, 'tur': 'npm'})

        python_pattern = r'\b(flask|django|requests|sqlalchemy|celery|pytest|pandas|numpy|scipy|scikit-learn|matplotlib|seaborn|jupyter|tensorflow|pytorch|keras|beautifulsoup|selenium|scrapy|fastapi|starlette|pydantic|sqlmodel|tortoise|peewee|alembic|black|pylint|flake8|mypy|poetry|pipenv)\b(?:[\s=<>~-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?)?'
        for m in re.finditer(python_pattern, metin_lower):
            name = m.group(1)
            ver = m.group(2) if len(m.groups()) > 1 else None
            deps.append({'ad': name, 'version': ver, 'tur': 'python'})

        # Additional simple heuristics for other ecosystems can be added if needed
        return deps

    def _aggregate_weekly_dependencies(self, yedi_gun_once: datetime) -> dict:
        db = session_al()
        try:
            rows = db.query(Zafiyet).filter(Zafiyet.bulunan_tarih >= yedi_gun_once).all()
            all_deps = {}
            for z in rows:
                metin = f"{z.baslik or ''} {z.aciklama or ''} {z.etkilenen_yazilimlar or ''}"
                deps = self._extract_dependencies(metin)
                for d in deps:
                    key = f"{d['ad']}-{d['tur']}"
                    if key not in all_deps:
                        all_deps[key] = {
                            'ad': d['ad'],
                            'tur': d['tur'],
                            'adet': 0,
                            'max_severity': None,
                            'cve_list': set()
                        }
                    all_deps[key]['adet'] += 1
                    if z.onem_derecesi:
                        if all_deps[key]['max_severity'] is None or self._onem_sira(z.onem_derecesi) > self._onem_sira(all_deps[key]['max_severity']):
                            all_deps[key]['max_severity'] = z.onem_derecesi
                    cve = self._cve_numarasi_bul(z)
                    if cve:
                        all_deps[key]['cve_list'].add(cve)

            # Convert to list and sort by adet
            deps_list = [
                {
                    'ad': v['ad'],
                    'tur': v['tur'],
                    'adet': v['adet'],
                    'max_severity': v['max_severity'].name if v['max_severity'] else None,
                    'cve_list': sorted(list(v['cve_list']))
                }
                for v in all_deps.values()
            ]
            deps_list.sort(key=lambda x: x['adet'], reverse=True)
            toplam = sum(d['adet'] for d in deps_list)
            return {'toplam': toplam, 'deps': deps_list}
        finally:
            db.close()

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

            trend_kayitlari = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi.isnot(None)
            ).all()

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

            remote_kritik_rows = db.query(Zafiyet).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.onem_derecesi == OnemDerecesi.KRITIK
            ).order_by(Zafiyet.bulunan_tarih.desc()).all()

          
            trend_gruplari = {}
            for z in trend_kayitlari:
                cve = self._cve_numarasi_bul(z)
                if cve:
                    anahtar = f"cve:{cve}"
                    grup_etiketi = cve
                else:
                    urun_etiketi = self._urun_etiketi_bul(z)
                    anahtar = f"urun:{urun_etiketi}"
                    grup_etiketi = urun_etiketi

                if anahtar not in trend_gruplari:
                    trend_gruplari[anahtar] = {
                        'anahtar': anahtar,
                        'baslik': z.baslik or '',
                        'kategori': z.kategori or 'Belirsiz',
                        'etkilenen_yazilimlar': z.etkilenen_yazilimlar or 'Bilinmiyor',
                        'onem_derecesi': z.onem_derecesi,
                        'url': z.url or '#',
                        'grup_etiketi': grup_etiketi,
                        'adet': 0,
                        'son_tarih': z.bulunan_tarih,
                        'onem_skor': self._onem_sira(z.onem_derecesi),
                    }

                g = trend_gruplari[anahtar]
                g['adet'] += 1

                if z.bulunan_tarih and (not g['son_tarih'] or z.bulunan_tarih > g['son_tarih']):
                    g['son_tarih'] = z.bulunan_tarih
                    g['baslik'] = z.baslik or g['baslik']
                    g['url'] = z.url or g['url']
                    g['kategori'] = z.kategori or g['kategori']
                    g['etkilenen_yazilimlar'] = z.etkilenen_yazilimlar or g['etkilenen_yazilimlar']

                skor = self._onem_sira(z.onem_derecesi)
                if skor > g['onem_skor']:
                    g['onem_skor'] = skor
                    g['onem_derecesi'] = z.onem_derecesi

            trend_sirali = self._trend_sirala(trend_gruplari, limit=10)

            trend_zafiyetler = [
                {
                    'baslik': r['baslik'],
                    'kategori': r['kategori'],
                    'etkilenen_yazilimlar': r['etkilenen_yazilimlar'],
                    'onem_derecesi_value': r['onem_derecesi'].value if r['onem_derecesi'] else 'Bilinmiyor',
                    'onem_derecesi_key': r['onem_derecesi'].name.lower() if r['onem_derecesi'] else 'bilinmiyor',
                    'url': r['url'] or '#',
                    'adet': r['adet'],
                    'son_tarih': r['son_tarih'].strftime('%d.%m.%Y') if r['son_tarih'] else '-'
                }
                for r in trend_sirali
            ]

            kategoriler = [
                {
                    'kategori': r.kategori,
                    'adet': r.adet
                }
                for r in kategori_rows
            ]

            # Veri kaynaklarına göre dağılım (Exploit-DB, 0day.today, GitHub, Telegram, vb.)
            kaynak_rows = db.query(
                Zafiyet.kaynak,
                func.count(Zafiyet.id).label('adet')
            ).filter(
                Zafiyet.bulunan_tarih >= yedi_gun_once,
                Zafiyet.kaynak.isnot(None)
            ).group_by(
                Zafiyet.kaynak
            ).order_by(
                func.count(Zafiyet.id).desc()
            ).all()

            kaynaklar = [{'kaynak': r.kaynak, 'adet': r.adet} for r in kaynak_rows]

            yama_gruplari = {}
            for z in trend_kayitlari:
                if z.onem_derecesi not in {OnemDerecesi.KRITIK, OnemDerecesi.YUKSEK}:
                    continue

                urun = self._urun_etiketi_bul(z)
                anahtar = urun.lower().strip() or "bilinmiyor"

                if anahtar not in yama_gruplari:
                    yama_gruplari[anahtar] = {
                        'urun': urun,
                        'adet': 0,
                        'kritik_adet': 0,
                        'yuksek_adet': 0,
                        'son_tarih': z.bulunan_tarih,
                        'ornek_baslik': z.baslik or '',
                        'ornek_url': z.url or '#',
                    }

                g = yama_gruplari[anahtar]
                g['adet'] += 1
                if z.onem_derecesi == OnemDerecesi.KRITIK:
                    g['kritik_adet'] += 1
                elif z.onem_derecesi == OnemDerecesi.YUKSEK:
                    g['yuksek_adet'] += 1

                if z.bulunan_tarih and (not g['son_tarih'] or z.bulunan_tarih > g['son_tarih']):
                    g['son_tarih'] = z.bulunan_tarih
                    g['ornek_baslik'] = z.baslik or g['ornek_baslik']
                    g['ornek_url'] = z.url or g['ornek_url']

            oncelikli_yama_listesi = [
                {
                    'urun': g['urun'],
                    'adet': g['adet'],
                    'kritik_adet': g['kritik_adet'],
                    'yuksek_adet': g['yuksek_adet'],
                    'son_tarih': g['son_tarih'].strftime('%d.%m.%Y') if g['son_tarih'] else '-',
                    'ornek_baslik': g['ornek_baslik'],
                    'ornek_url': g['ornek_url'] or '#',
                }
                for g in sorted(
                    yama_gruplari.values(),
                    key=lambda x: (
                        x['kritik_adet'],
                        x['adet'],
                        x['son_tarih'] or datetime.min,
                    ),
                    reverse=True,
                )[:10]
            ]

            remote_kritik_liste = []
            for z in remote_kritik_rows:
                metin = " ".join(
                    [
                        z.baslik or "",
                        z.aciklama or "",
                        z.kategori or "",
                        z.etkilenen_yazilimlar or "",
                    ]
                )
                if REMOTE_PATTERN.search(metin):
                    remote_kritik_liste.append(
                        {
                            'baslik': z.baslik or '',
                            'url': z.url or '#',
                            'etkilenen_yazilimlar': z.etkilenen_yazilimlar or '',
                            'bulunan_tarih': z.bulunan_tarih.strftime('%d.%m.%Y') if z.bulunan_tarih else '-',
                        }
                    )

            return {
                'toplam': toplam,
                'kritik': kritik,
                'yuksek': yuksek,
                'orta': orta,
                'dusuk': dusuk,
                'trend_zafiyetler': trend_zafiyetler,
                'kategoriler': kategoriler,
                'oncelikli_yama_listesi': oncelikli_yama_listesi,
                'remote_kritik_liste': remote_kritik_liste,
                'remote_kritik_sayisi': len(remote_kritik_liste),
                'kaynaklar': kaynaklar,
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
                        {baslik}
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

        yama_html = ""
        for i, y in enumerate(veri.get('oncelikli_yama_listesi', []), 1):
            urun = y['urun']
            baslik = y['ornek_baslik']
            yama_html += f"""
            <div style="border-left:4px solid #f59e0b; padding:12px 15px;
                        background:#2b220c; border-radius:0 8px 8px 0; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start;">
                    <div style="flex:1; min-width:0;">
                        <div style="color:#fcd34d; font-weight:700; font-size:15px; margin-bottom:4px;">
                            {i}. {urun[:50] if urun else 'bilinmiyor'}
                        </div>
                        <a href="{y['ornek_url']}" style="color:#fde68a; text-decoration:none; font-size:13px; line-height:1.5;">
                            {baslik}
                        </a>
                    </div>
                    <div style="text-align:right; white-space:nowrap; font-size:12px;">
                        <div style="color:#fef3c7; font-weight:700;">Toplam: {y['adet']}</div>
                        <div style="color:#fca5a5;">Kritik: {y['kritik_adet']}</div>
                        <div style="color:#fed7aa;">Yüksek: {y['yuksek_adet']}</div>
                        <div style="color:#a1a1aa; margin-top:4px;">Son: {y['son_tarih']}</div>
                    </div>
                </div>
            </div>"""

        remote_kritik_html = ""
        for i, z in enumerate(veri.get('remote_kritik_liste', []), 1):
            baslik = z['baslik']
            remote_kritik_html += f"""
            <div style="border-left:4px solid #ef4444; padding:12px 15px;
                        background:#2b0b0b; border-radius:0 8px 8px 0; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <a href="{z['url']}" style="color:#ff7a7a; text-decoration:none;
                               font-weight:700; font-size:14px; flex:1;">
                        {i}. {baslik}
                    </a>
                    <span style="color:#999; font-size:12px; margin-left:10px; white-space:nowrap;">
                        {z['bulunan_tarih']}
                    </span>
                </div>
                {f'<div style="color:#999; font-size:12px; margin-top:5px;">💻 {z["etkilenen_yazilimlar"][:50]}</div>' if z['etkilenen_yazilimlar'] else ''}
            </div>"""

        
        ozet_html = ""
        for paragraf in ai_ozet.split('\n\n'):
            if paragraf.strip():
                ozet_html += f'<p style="margin-bottom:15px; line-height:1.7;">{paragraf.strip()}</p>'  # ✅ EKLENDİ

        if veri.get('oncelikli_yama_listesi'):
            yama_bolumu = f"""
        <div style="background:#1a1a2e; border:1px solid #f59e0b; border-radius:12px;
                    padding:25px; margin-bottom:30px;">
            <h2 style="color:#f59e0b; margin:0 0 8px; font-size:1.2rem;">
                 Öncelikli Yama Listesi
            </h2>
            <p style="color:#fcd34d; margin:0 0 15px; font-size:13px; line-height:1.5;">
                Kritik ve yüksek bulgular, etkilenen ürün bazında önceliklendirilmiştir.
            </p>
            {yama_html}
        </div>"""
        else:
            yama_bolumu = "" 

        if veri.get('remote_kritik_liste'):
            remote_kritik_bolum = f"""
        <div style="background:linear-gradient(135deg,#2a1010 0%, #1a1a2e 55%); border:2px solid #ef4444; border-radius:14px;
                    box-shadow:0 0 0 2px rgba(239,68,68,0.15), 0 8px 30px rgba(239,68,68,0.12);
                    padding:25px; margin-bottom:30px;">
            <h2 style="color:#fecaca; margin:0 0 10px; font-size:1.35rem; letter-spacing:0.3px;">
                 ALARM: Remote Kritik Zafiyetler
            </h2>
            <p style="color:#fca5a5; font-size:13px; margin:0 0 14px; line-height:1.5;">
                Uzaktan istismar riski taşıyan ve haftanın en öncelikli aksiyon gerektiren kritik zafiyetleri.
            </p>
            <div style="display:inline-block; background:#ef4444; color:#fff; font-weight:800; font-size:13px;
                        padding:6px 12px; border-radius:999px; margin-bottom:14px;">
                Toplam Remote Kritik: {veri.get('remote_kritik_sayisi', 0)}
            </div>
            {remote_kritik_html}
        </div>"""
        else:
            remote_kritik_bolum = """
        <div style="background:linear-gradient(135deg,#1f2a2a 0%, #1a1a2e 55%); border:1px solid #10b981; border-radius:12px;
                    padding:20px; margin-bottom:30px;">
            <h2 style="color:#86efac; margin:0 0 8px; font-size:1.2rem;">
                Remote Kritik Alarm Durumu
            </h2>
            <p style="color:#a7f3d0; margin:0; font-size:13px;">
                Bu hafta remote-kritik zafiyet tespit edilmedi.
            </p>
        </div>"""

        # --- Kaynaklar bölümü oluştur ---
        kaynaklar_bolum = ""
        if veri.get('kaynaklar'):
            k_html = ""
            for k in veri['kaynaklar']:
                k_html += f"<div style=\"display:flex;justify-content:space-between;padding:8px 12px;border-bottom:1px solid #1e1e2e;\">"
                k_html += f"<div style=\"color:#cbd5e1;\">{k['kaynak']}</div>"
                k_html += f"<div style=\"background:#00d4ff;color:#081025;padding:4px 10px;border-radius:14px;font-weight:700;\">{k['adet']}</div>"
                k_html += "</div>"

            kaynaklar_bolum = f"""
        <div style=\"background:#1a1a2e; border:1px solid #2a2a4e; border-radius:12px; padding:20px; margin-bottom:30px;\">
            <h2 style=\"color:#00d4ff; margin:0 0 12px; font-size:1.1rem;\">📡 Veri Kaynakları Dağılımı</h2>
            <div style=\"border-radius:8px; overflow:hidden; margin-top:10px;\">{k_html}</div>
        </div>
            """

        # --- Dependency özeti ---
        dep_info = self._aggregate_weekly_dependencies(veri['baslangic'])
        dep_bolum = ""
        if dep_info and dep_info.get('deps'):
            d_html = ""
            for d in dep_info['deps'][:5]:
                d_html += f"<div style=\"display:flex;justify-content:space-between;padding:8px 12px;border-bottom:1px solid #1e1e2e;\">"
                d_html += f"<div style=\"color:#cbd5e1;\">{d['ad']} <span style=\"color:#9ca3af;font-size:12px;\">({d['tur']})</span></div>"
                d_html += f"<div style=\"background:#f59e0b;color:#081025;padding:4px 10px;border-radius:14px;font-weight:700;\">{d['adet']}</div>"
                d_html += "</div>"

            dep_bolum = f"""
        <div style=\"background:#1a1a2e; border:1px solid #2a2a4e; border-radius:12px; padding:20px; margin-bottom:30px;\">
            <h2 style=\"color:#f59e0b; margin:0 0 12px; font-size:1.1rem;\">🔗 Dependency Özeti</h2>
            <p style=\"color:#9ca3af;margin:0 0 10px;\">Haftalık tespit edilen bağımlılıklardan en sık görülenler (top 5) ve toplam referans sayısı.</p>
            <div style=\"border-radius:8px; overflow:hidden; margin-top:10px;\">{d_html}</div>
            <div style=\"margin-top:10px;color:#9ca3af;\">Toplam dependency referans: <strong style=\"color:#fff;\">{dep_info['toplam']}</strong></div>
        </div>
            """

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

        {yama_bolumu}

        {dep_bolum}

        {kaynaklar_bolum}

        {remote_kritik_bolum}

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