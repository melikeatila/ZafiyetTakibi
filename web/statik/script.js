// ============= DEPENDENCY FUNCTIONS =============

async function loadDependencies() {
    console.log('[DEBUG] loadDependencies çalışıyor...');
    try {
        const response = await fetch('/api/dependencies?limit=100');
        console.log('[DEBUG] Response status:', response.status);
        const data = await response.json();

        // Update stats
        document.getElementById('dep-toplam').textContent = data.toplam;
        document.getElementById('dep-npm').textContent = data.kaynaklar.npm || 0;
        document.getElementById('dep-python').textContent = data.kaynaklar.python || 0;
        document.getElementById('dep-java').textContent = data.kaynaklar.java || 0;

        // Display top 10 dependencies
        const topDeps = data.dependencies.slice(0, 10);
        const tbody = document.getElementById('top-deps-body');
        tbody.innerHTML = '';

        topDeps.forEach((dep, index) => {
            const severityClass = dep.max_severity === 'Kritik' ? 'kritik' :
                                 dep.max_severity === 'Yüksek' ? 'yuksek' :
                                 dep.max_severity === 'Orta' ? 'orta' :
                                 dep.max_severity === 'Düşük' ? 'dusuk' : 'bilinmiyor';
            
            const cveCount = dep.cve_list ? dep.cve_list.length : 0;
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-weight: 600; color: #667eea;">${index + 1}</td>
                <td style="font-weight: 600;">${dep.ad}</td>
                <td><span style="background: rgba(102, 126, 234, 0.2); color: #667eea; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;">${dep.tur.toUpperCase()}</span></td>
                <td><span style="background: rgba(239, 68, 68, 0.1); color: #ef4444; padding: 3px 8px; border-radius: 4px; font-weight: 600;">${dep.adet}</span></td>
                <td><span class="badge badge-${severityClass}" style="display: inline-block;">${dep.max_severity || 'Bilinmiyor'}</span></td>
                <td style="color: #888; font-size: 13px;">${cveCount} CVE</td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Dependency yükleme hatası:', error);
    }
}

async function searchDependency() {
    const searchTerm = document.getElementById('dep-search').value.toLowerCase();
    const typeFilter = document.getElementById('dep-type-filter').value;
    const resultsDiv = document.getElementById('dep-search-results');

    if (!searchTerm.trim()) {
        resultsDiv.style.display = 'none';
        return;
    }

    try {
        const response = await fetch(`/api/dependencies/${encodeURIComponent(searchTerm)}`);
        if (!response.ok) {
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = `<div style="background: #fee; padding: 15px; border-radius: 8px; color: #c53030; border: 1px solid #fc8181;">❌ "${searchTerm}" paketi bulunamadı</div>`;
            return;
        }

        const dep = await response.json();

        // Filter by type if selected
        if (typeFilter && dep.tur !== typeFilter) {
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = `<div style="background: #fee; padding: 15px; border-radius: 8px; color: #c53030;">Bu paket ${typeFilter} türünde değildir. (Tür: ${dep.tur})</div>`;
            return;
        }

        resultsDiv.style.display = 'block';
        const severityClass = dep.max_severity === 'Kritik' ? 'kritik' :
                             dep.max_severity === 'Yüksek' ? 'yuksek' :
                             dep.max_severity === 'Orta' ? 'orta' :
                             dep.max_severity === 'Düşük' ? 'dusuk' : 'bilinmiyor';

        let html = `
            <div style="background: var(--bg-hover); padding: 20px; border-radius: 12px; border-left: 4px solid #667eea;">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 20px;">
                    <div>
                        <h4 style="margin: 0 0 8px 0; font-size: 18px;">${dep.ad}</h4>
                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                            <span style="background: rgba(102, 126, 234, 0.2); color: #667eea; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;">${dep.tur.toUpperCase()}</span>
                            ${dep.version ? `<span style="color: #888; font-size: 12px;">v${dep.version}</span>` : ''}
                        </div>
                    </div>
                    <span class="badge badge-${severityClass}" style="display: inline-block; padding: 8px 12px;">${dep.max_severity || 'Bilinmiyor'}</span>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px;">
                    <div>
                        <div style="color: #888; font-size: 12px;">Toplam Zafiyet</div>
                        <div style="font-size: 24px; font-weight: 700; color: #ef4444;">${dep.toplam_zafiyetler}</div>
                    </div>
                    <div>
                        <div style="color: #888; font-size: 12px;">CVE Sayısı</div>
                        <div style="font-size: 24px; font-weight: 700; color: #f59e0b;">${dep.cve_list ? dep.cve_list.length : 0}</div>
                    </div>
                </div>

                ${dep.cve_list && dep.cve_list.length > 0 ? `
                    <div style="margin-bottom: 20px;">
                        <h5 style="margin: 0 0 10px 0; color: #888; font-size: 12px; font-weight: 600; text-transform: uppercase;">İlişkili CVE'ler</h5>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                            ${dep.cve_list.slice(0, 10).map(cve => `<span style="background: rgba(239, 68, 68, 0.1); color: #ef4444; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">${cve}</span>`).join('')}
                            ${dep.cve_list.length > 10 ? `<span style="color: #888; padding: 4px 8px; font-size: 11px;">+${dep.cve_list.length - 10} daha</span>` : ''}
                        </div>
                    </div>
                ` : ''}

                ${dep.zafiyetler && dep.zafiyetler.length > 0 ? `
                    <div>
                        <h5 style="margin: 0 0 10px 0; color: #888; font-size: 12px; font-weight: 600; text-transform: uppercase;">İlişkili Zafiyetler (${dep.zafiyetler.length})</h5>
                        <div style="max-height: 400px; overflow-y: auto;">
                            ${dep.zafiyetler.map(z => `
                                <div class="dep-card" ${z.url ? `style="cursor: pointer;" onclick="window.open('${z.url}', '_blank')"` : ''}>
                                    <div class="dep-card-header">
                                        <span class="dep-card-name">${z.baslik}</span>
                                        <span class="badge badge-${z.onem === 'Kritik' ? 'kritik' : z.onem === 'Yüksek' ? 'yuksek' : z.onem === 'Orta' ? 'orta' : 'dusuk'}">${z.onem}</span>
                                    </div>
                                    <div class="dep-card-stats">
                                        <span class="dep-stat">📍 ${z.kaynak}</span>
                                        ${z.cve ? `<span class="dep-stat">🔐 <span class="dep-stat-value">${z.cve}</span></span>` : ''}
                                        <span class="dep-stat">🏷️ ${z.kategori || 'Diğer'}</span>
                                    </div>
                                    ${z.url ? `<div style="margin-top: 8px; font-size: 12px; color: #667eea; text-decoration: underline;">🔗 Detay</div>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
        resultsDiv.innerHTML = html;
    } catch (error) {
        console.error('Arama hatası:', error);
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `<div style="background: #fee; padding: 15px; border-radius: 8px; color: #c53030;">❌ Bir hata oluştu: ${error.message}</div>`;
    }
}

// Page load'da dependency'leri yükle
document.addEventListener('DOMContentLoaded', function() {
    loadDependencies();
    
    // Enter'a basınca ara
    const depSearchInput = document.getElementById('dep-search');
    if (depSearchInput) {
        depSearchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                searchDependency();
            }
        });
    }
});

async function ara() {
    const yazilim = document.getElementById('yazilim').value;
    const onem = document.getElementById('onem').value;
    const kategori = document.getElementById('kategori').value;

    
    let url = '/api/zafiyetler?limit=100';
    if (yazilim) url += `&yazilim=${encodeURIComponent(yazilim)}`;
    if (onem) url += `&onem=${onem}`;
    if (kategori) url += `&kategori=${encodeURIComponent(kategori)}`;

    const sonuclarDiv = document.getElementById('sonuclar');
    sonuclarDiv.innerHTML = '<p style="text-align:center;"> Aranıyor...</p>';

    try {
        const response = await fetch(url);
        const data = await response.json();

        if (data.zafiyetler.length === 0) {
            sonuclarDiv.innerHTML = '<p style="text-align:center; color: #888;">Sonuç bulunamadı.</p>';
            return;
        }

       
        let html = '<table class="zafiyet-table"><thead><tr>';
        html += '<th>Kaynak</th><th>Önem</th><th>Başlık</th><th>Yazılım</th><th>Kategori</th><th>Tarih</th><th></th>';
        html += '</tr></thead><tbody>';

        const normalizeOnem = (onem) => {
            const v = (onem || '').toString().toUpperCase();
            if (v.includes('KRITIK') || v.includes('KRİTİK')) return 'kritik';
            if (v.includes('YUKSEK') || v.includes('YÜKSEK')) return 'yuksek';
            if (v.includes('ORTA')) return 'orta';
            if (v.includes('DUSUK') || v.includes('DÜŞÜK')) return 'dusuk';
            return 'bilinmiyor';
        };

        data.zafiyetler.forEach(z => {
            const onemClass = normalizeOnem(z.onem_derecesi);
            html += `<tr class="severity-row sev-${onemClass}">`;
            
            // Kaynak badge
            const kaynak = (z.kaynak || '').toLowerCase();
            if (kaynak === 'github') {
                html += `<td><span class="source-badge github"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg></span></td>`;
            } else if (kaynak === 'telegram') {
                html += `<td><span class="source-badge telegram"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336a8.154 8.154 0 0 1-.188.186c-.38.366-.664.64.015 1.088.327.216.589.393.85.571.284.194.568.387.936.629.093.06.183.125.27.187.331.236.63.448.997.414.214-.02.435-.22.547-.82.265-1.417.786-4.486.906-5.751a1.426 1.426 0 0 0-.013-.315.337.337 0 0 0-.114-.217.526.526 0 0 0-.31-.093c-.3.005-.763.166-2.984 1.09z"/></svg></span></td>`;
            } else if (kaynak === 'exploit-db') {
                html += `<td><span class="source-badge unknown" style="background:#ff5722;">Exploit-DB</span></td>`;
            } else if (kaynak === '0day.today') {
                html += `<td><span class="source-badge unknown" style="background:#9c27b0;">0-Day</span></td>`;
            } else {
                html += `<td><span class="source-badge unknown">${z.kaynak || '?'}</span></td>`;
            }
            
            html += `<td><span class="badge badge-${onemClass}">${z.onem_derecesi}</span></td>`;
            
            // Başlığı link yap, hem de Detay butonu kalsın
            if (z.url) {
                html += `<td class="baslik-cell"><a href="${z.url}" target="_blank" style="text-decoration:none; color:inherit; font-weight:600;">${z.baslik}</a></td>`;
            } else {
                html += `<td class="baslik-cell">${z.baslik}</td>`;
            }
            
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
        sonuclarDiv.innerHTML = '<p style="color: #ff4444; text-align: center;"> Bir hata oluştu. Lütfen tekrar deneyin.</p>';
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