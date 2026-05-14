$base = 'c:\projects\ZafiyetTakibi'
$python = "$base\venv\Scripts\python.exe"
cd $base
& $python -c "
import sys, os
sys.path.insert(0, 'c:\\projects\\ZafiyetTakibi')
from raporlama.mail_gonder import MailGonderici
from datetime import datetime

try:
    gonderici = MailGonderici()
    sonuc = gonderici.haftalik_rapor_gonder()
    print(f'Rapor gonderimi tamamlandi - Basarili: {sonuc.get(\"basarili\", 0)}, Basarisiz: {sonuc.get(\"basarisiz\", 0)}')
except Exception as e:
    print(f'Hata: {str(e)}')
    import traceback
    traceback.print_exc()
"
