"""
Vulnerability Trends Toplayıcısı (GHDB yerine)
Odak: En popüler ve trending vulnerabilities'ler
UYARI: GHDB RSS 404 döndüğü için bu alternatif kaynak kullanılıyor
"""

import requests
import feedparser
import sqlite3
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import logging
from bs4 import BeautifulSoup
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GHDBCollector:
    """Vulnerability Trends'den trending açıkları toplayan sınıf (GHDB yerine)"""
    
    # Exploit-DB RSS (çalışan kaynak)
    EXPLOITDB_RSS = "https://www.exploit-db.com/rss.xml"
    # VulnDB RSS (alternatif - çalışan kaynaklar)
    TRENDING_SOURCES = [
        "https://www.exploit-db.com/rss.xml",  # Exploit DB - en etkili
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZafiyetTakibi/1.0 (+https://github.com)'
        })
        
        # SQLite veri tabanı (opsiyonel)
        self.db_path = None
    # ============= METHOD 1: RSS FEED (TRENDING) =============
    def get_latest_from_rss(self, limit: int = 50) -> List[Dict]:
        """
        Exploit-DB RSS'den trending exploit'leri çeker
        GHDB RSS 404 döndüğü için Exploit-DB trending'i kullanıyoruz
        Bunu başka kaynaklardaki exploit'lerden ayırt ediyoruz
        """
        try:
            logger.info("GHDB/Trending exploit'leri RSS'den çekiliyor...")
            feed = feedparser.parse(self.EXPLOITDB_RSS)
            
            dorks = []
            # Sadece ilk 10-15 kaydı al (trending olarak işaretle)
            trending_limit = min(15, limit)
            
            for entry in feed.entries[:trending_limit]:
                exploit_info = {
                    'title': entry.get('title', 'Untitled'),
                    'url': entry.get('link', ''),
                    'published': entry.get('published', ''),
                    'description': entry.get('summary', '')[:300],
                    'category': 'Trending Exploit',
                    'author': entry.get('author', 'Exploit-DB'),
                    'severity': self._extract_severity(entry.get('summary', '')),
                    'source': 'trending-ghdb',
                    'collected_at': datetime.now().isoformat()
                }
                dorks.append(exploit_info)
            
            logger.info(f"✓ {len(dorks)} trending exploit RSS'den toplandı")
            return dorks
            
        except Exception as e:
            logger.error(f"RSS Feed hatası: {e}")
            return []
    
    # ============= METHOD 2: API SEARCH =============
    def search_dorks(self, keyword: str, limit: int = 50) -> List[Dict]:
        """
        Exploit-DB API kullanarak GHDB'de dork arama
        keyword: 'wordpress', 'apache', 'webcam', etc.
        """
        try:
            logger.info(f"GHDB'de '{keyword}' aranıyor...")
            
            params = {
                'q': keyword,
                'type': 'ghdb',
                'sort': 'date',
                'order': 'desc',
                'limit': min(limit, 500)
            }
            
            response = self.session.get(
                f"{self.API_BASE}/search",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            dorks = []
            
            for item in data.get('data', []):
                dork = {
                    'id': item.get('ghdb_id'),
                    'title': item.get('title'),
                    'description': item.get('description'),
                    'dork_query': item.get('query'),  # Asıl Google dork
                    'category': item.get('category'),
                    'author': item.get('author'),
                    'type': item.get('type'),
                    'date': item.get('date'),
                    'url': f"https://www.exploit-db.com/ghdb/{item.get('ghdb_id')}",
                    'source': 'ghdb-api',
                    'collected_at': datetime.now().isoformat()
                }
                dorks.append(dork)
            
            logger.info(f"✓ {len(dorks)} dork bulundu")
            return dorks
            
        except Exception as e:
            logger.error(f"API arama hatası: {e}")
            return []
    
    # ============= METHOD 3: CATEGORY FILTER =============
    def get_by_category(self, category: str, limit: int = 50) -> List[Dict]:
        """
        Kategoriye göre GHDB dork'larını çeker
        categories: 'files', 'dirs', 'documents', 'servers', 'webcams', etc.
        """
        try:
            logger.info(f"'{category}' kategorisinden dork'lar çekiliyor...")
            
            # Category ID'si elde et
            category_name = self.CATEGORIES.get(category, category)
            
            params = {
                'category': category_name,
                'sort': 'date',
                'order': 'desc',
                'limit': min(limit, 500)
            }
            
            response = self.session.get(
                f"{self.API_BASE}/search",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            dorks = []
            
            for item in data.get('data', []):
                dork = {
                    'id': item.get('ghdb_id'),
                    'title': item.get('title'),
                    'dork_query': item.get('query'),
                    'category': category_name,
                    'description': item.get('description', ''),
                    'date': item.get('date'),
                    'author': item.get('author'),
                    'url': f"https://www.exploit-db.com/ghdb/{item.get('ghdb_id')}",
                    'source': 'ghdb-category',
                    'collected_at': datetime.now().isoformat()
                }
                dorks.append(dork)
            
            logger.info(f"✓ {len(dorks)} dork '{category}' kategorisinden toplandı")
            return dorks
            
        except Exception as e:
            logger.error(f"Kategori çekme hatası: {e}")
            return []
    
    # ============= METHOD 4: WEB SCRAPING =============
    def scrape_ghdb_page(self, page: int = 1) -> List[Dict]:
        """
        GHDB web sayfasını scraping ile çeker
        ⚠ Rate limiting'e dikkat
        """
        try:
            logger.info(f"GHDB sayfa #{page} scraping yapılıyor...")
            
            params = {'p': page}
            response = self.session.get(
                self.GHDB_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            dorks = []
            
            # Dork tablosunu bul
            rows = soup.find_all('tr', class_='ghdb-row')
            
            for row in rows:
                try:
                    tds = row.find_all('td')
                    if len(tds) >= 4:
                        # ID
                        id_elem = tds[0].find('a')
                        # Title/Query
                        title_elem = tds[1].find('a')
                        # Type
                        type_elem = tds[2]
                        # Category
                        category_elem = tds[3]
                        
                        if title_elem:
                            dork = {
                                'id': id_elem.get_text(strip=True) if id_elem else '',
                                'title': title_elem.get_text(strip=True),
                                'dork_query': title_elem.get_text(strip=True),
                                'type': type_elem.get_text(strip=True),
                                'category': category_elem.get_text(strip=True),
                                'url': title_elem.get('href'),
                                'source': 'ghdb-scrape',
                                'collected_at': datetime.now().isoformat()
                            }
                            dorks.append(dork)
                except Exception as e:
                    logger.warning(f"Row parse hatası: {e}")
                    continue
            
            logger.info(f"✓ {len(dorks)} dork scraping'den toplandı")
            return dorks
            
        except Exception as e:
            logger.error(f"Scraping hatası: {e}")
            return []
    
    # ============= METHOD 5: DORK DETAIL =============
    def get_dork_details(self, ghdb_id: int) -> Optional[Dict]:
        """
        Belirli bir GHDB dork'un detaylı bilgisini çeker
        """
        try:
            url = f"https://www.exploit-db.com/ghdb/{ghdb_id}"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Parse bilgiler
            title = soup.find('h1', class_='ghdb-title')
            description = soup.find('div', class_='ghdb-description')
            dork_query = soup.find('code', class_='dork-query')
            
            detail = {
                'id': ghdb_id,
                'title': title.get_text(strip=True) if title else '',
                'description': description.get_text(strip=True) if description else '',
                'dork_query': dork_query.get_text(strip=True) if dork_query else '',
                'url': url,
                'source': 'ghdb-detail',
                'collected_at': datetime.now().isoformat()
            }
            
            logger.info(f"✓ GHDB #{ghdb_id} detail çekildi")
            return detail
            
        except Exception as e:
            logger.error(f"Detail çekme hatası: {e}")
            return None
    
    # ============= METHOD 6: CSV EXPORT =============
    def download_csv_export(self, output_file: str = 'ghdb_export.csv') -> bool:
        """
        GHDB'nin tüm CSV export'ını indir
        Sıra dışı bir yöntem, tüm dork'ları bir kez indir
        """
        try:
            logger.info(f"GHDB CSV export'u {output_file} olarak indirildi...")
            
            url = "https://www.exploit-db.com/csv/ghdb.csv"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            with open(output_file, 'wb') as f:
                f.write(response.content)
            
            logger.info(f"✓ CSV indirildi: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"CSV export hatası: {e}")
            return False
    
    # ============= METHOD 7: ADVANCED FILTERING =============
    def get_high_impact_dorks(self, limit: int = 30) -> List[Dict]:
        """
        Yüksek etki potansiyeline sahip dork'ları filtrele
        (webcam, server detection, sensitive files vb.)
        """
        try:
            logger.info("Yüksek etki dork'lar çekiliyor...")
            
            high_impact_categories = [
                'webcams', 'servers', 'networks', 'printers'
            ]
            
            all_dorks = []
            for category in high_impact_categories:
                dorks = self.get_by_category(category, limit=10)
                all_dorks.extend(dorks)
            
            logger.info(f"✓ {len(all_dorks)} yüksek etki dork toplandı")
            return all_dorks[:limit]
            
        except Exception as e:
            logger.error(f"Yüksek etki dork çekme hatası: {e}")
            return []
    
    # ============= HELPER FUNCTIONS =============
    def _parse_ghdb_entry(self, entry) -> Optional[Dict]:
        """RSS entry'sinden GHDB bilgisi çıkart"""
        try:
            return {
                'title': entry.get('title', ''),
                'dork_query': entry.get('summary', ''),
                'url': entry.get('link', ''),
                'published': entry.get('published', ''),
                'source': 'ghdb-rss',
                'collected_at': datetime.now().isoformat()
            }
        except Exception as e:
            logger.warning(f"Entry parse hatası: {e}")
            return None
    
    def extract_operators_from_dork(self, dork_query: str) -> Dict[str, List[str]]:
        """
        Dork sorgusundan Google operatörlerini çıkart
        """
        operators = {
            'site': re.findall(r'site:(\S+)', dork_query),
            'filetype': re.findall(r'filetype:(\w+)', dork_query),
            'inurl': re.findall(r'inurl:(\S+)', dork_query),
            'intitle': re.findall(r'intitle:(\S+)', dork_query),
            'intext': re.findall(r'intext:(\S+)', dork_query),
            'cache': re.findall(r'cache:(\S+)', dork_query),
        }
        
        return {k: v for k, v in operators.items() if v}
    
    def get_operator_stats(self, dorks: List[Dict]) -> Dict:
        """
        Dork listesinden operator istatistiklerini al
        """
        stats = {
            'total_dorks': len(dorks),
            'site_usage': 0,
            'filetype_usage': 0,
            'inurl_usage': 0,
            'intitle_usage': 0,
        }
        
        for dork in dorks:
            query = dork.get('dork_query', '').lower()
            if 'site:' in query:
                stats['site_usage'] += 1
            if 'filetype:' in query:
                stats['filetype_usage'] += 1
            if 'inurl:' in query:
                stats['inurl_usage'] += 1
            if 'intitle:' in query:
                stats['intitle_usage'] += 1
        
        return stats
    
    def _extract_severity(self, content: str) -> str:
        """
        İçerikten tehdit seviyesini çıkart
        """
        content_lower = content.lower()
        
        if any(word in content_lower for word in ['critical', 'kritik', 'rce', 'remote code']):
            return 'YUKSEK'
        elif any(word in content_lower for word in ['high', 'yüksek', 'sql injection', 'xss']):
            return 'YUKSEK'
        elif any(word in content_lower for word in ['medium', 'orta']):
            return 'ORTA'
        else:
            return 'DUSUK'


# ============= KULLANIM ÖRNEĞİ =============
if __name__ == "__main__":
    collector = GHDBCollector()
    
    # RSS Feed'den son dork'lar
    print("\n=== RSS Feed'den Son 5 Dork ===")
    rss_dorks = collector.get_latest_from_rss(limit=5)
    for dork in rss_dorks[:3]:
        print(f"- {dork['title'][:60]}")
        print(f"  Query: {dork['dork_query'][:70]}")
    
    # Kategoriye göre
    print("\n=== 'Webcams' Kategorisinden ===")
    webcams = collector.get_by_category('webcams', limit=5)
    for dork in webcams[:3]:
        print(f"- {dork['title'][:60]}")
        operators = collector.extract_operators_from_dork(dork['dork_query'])
        print(f"  Operators: {operators}")
    
    # Arama yapma
    print("\n=== 'WordPress' Arama ===")
    search = collector.search_dorks('WordPress', limit=5)
    for dork in search[:3]:
        print(f"- {dork['title'][:60]}")
    
    # Yüksek etki dork'lar
    print("\n=== Yüksek Etki Dork'lar ===")
    high_impact = collector.get_high_impact_dorks(limit=5)
    for dork in high_impact:
        print(f"- [{dork['category']}] {dork['title'][:50]}")
    
    # Operator istatistikleri
    print("\n=== Operator İstatistikleri ===")
    if search:
        stats = collector.get_operator_stats(search)
        for key, value in stats.items():
            print(f"  {key}: {value}")
