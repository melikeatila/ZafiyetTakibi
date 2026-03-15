async function ara() {
    const yazilim = document.getElementById('yazilim').value;
    const onem = document.getElementById('onem').value;
    const kategori = document.getElementById('kategori').value;

    
    let url = '/api/zafiyetler?limit=100';
    if (yazilim) url += `&yazilim=${encodeURIComponent(yazilim)}`;
    if (onem) url += `&onem=${onem}`;
    if (kategori) url += `&kategori=${encodeURIComponent(kategori)}`;

    const sonuclarDiv = document.getElementById('sonuclar');
    sonuclarDiv.innerHTML = '<p style="text-align:center;">🔍 Aranıyor...</p>';

    try {
        const response = await fetch(url);
        const data = await response.json();

        if (data.zafiyetler.length === 0) {
            sonuclarDiv.innerHTML = '<p style="text-align:center; color: #888;">Sonuç bulunamadı.</p>';
            return;
        }

       
        let html = '<table class="zafiyet-table"><thead><tr>';
        html += '<th>Önem</th><th>Başlık</th><th>Yazılım</th><th>Kategori</th><th>Tarih</th><th></th>';
        html += '</tr></thead><tbody>';

        data.zafiyetler.forEach(z => {
            html += '<tr>';
            html += `<td><span class="badge badge-${z.onem_derecesi}">${z.onem_derecesi}</span></td>`;
            html += `<td class="baslik-cell">${z.baslik.substring(0, 80)}${z.baslik.length > 80 ? '...' : ''}</td>`;
            html += `<td>${z.etkilenen_yazilimlar}</td>`;
            html += `<td>${z.kategori}</td>`;
            
            
            const tarih = z.bulunan_tarih ? new Date(z.bulunan_tarih).toLocaleDateString('tr-TR') : '-';
            html += `<td>${tarih}</td>`;
            
            html += `<td>${z.url ? `<a href="${z.url}" target="_blank" class="btn-link">Detay</a>` : ''}</td>`;
            html += '</tr>';
        });

        html += '</tbody></table>';
        html += `<p style="margin-top: 20px; color: #888; text-align: center;">Toplam <strong>${data.toplam}</strong> sonuç bulundu (gösterilen: ${data.zafiyetler.length})</p>`;
        
        sonuclarDiv.innerHTML = html;
    } catch (error) {
        console.error('Arama hatası:', error);
        sonuclarDiv.innerHTML = '<p style="color: #ff4444; text-align: center;">❌ Bir hata oluştu. Lütfen tekrar deneyin.</p>';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const inputs = ['yazilim', 'kategori'];
    inputs.forEach(id => {
        document.getElementById(id)?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') ara();
        });
    });
});