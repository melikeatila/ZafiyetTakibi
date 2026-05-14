"""
Snyk Vulnerability Database Toplayıcısı (Eski 0day.today yerine)
https://snyk.io/vulnerability-scanner/
Odak: Resmi CVE'ler ve open-source kütüphane zafiyetleri
"""

import requests
import feedparser
from datetime import datetime
from typing import List, Dict, Optional
import logging
from bs4 import BeautifulSoup
import re
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ZeroDayTodayCollector:
    """Snyk Vulnerability Database'den zafiyetleri toplayan sınıf (NVD yerine)"""
    
    MAIN_URL = "https://snyk.io"
    # Snyk public API
    SNYK_API = "https://snyk.io/api/v1"
    # Fallback: Snyk blog RSS
    RSS_URL = "https://snyk.io/blog/feed/"
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    # ============= METHOD 1: RSS FEED =============
    def get_latest_from_rss(self, limit: int = 50) -> List[Dict]:
        """
        Snyk Blog RSS'den son zafiyet haberlerini çeker
        """
        try:
            logger.info("Snyk Blog'dan veri çekiliyor...")
            feed = feedparser.parse(self.RSS_URL)
            
            cves = []
            
            for entry in feed.entries[:limit]:
                title = entry.get('title', '')
                summary = entry.get('summary', '') or entry.get('description', '')
                
                # CVE ID'si içeriyorsa ekle
                cve_match = re.search(r'CVE-\d{4}-\d+', title + ' ' + summary)
                cve_id = cve_match.group(0) if cve_match else None
                
                cve = {
                    'title': title[:200],
                    'url': entry.get('link', ''),
                    'published': entry.get('published', ''),
                    'content': summary[:500],
                    'author': 'Snyk Security',
                    'category': 'Vulnerability Report',
                    'severity': self._extract_severity(summary),
                    'source': 'snyk-blog',
                    'collected_at': datetime.now().isoformat(),
                    'cve_id': cve_id
                }
                cves.append(cve)
            
            logger.info(f"✓ {len(cves)} zafiyet Snyk'tan toplandı")
            return cves
            
        except Exception as e:
            logger.error(f"Snyk Blog RSS hatası: {e}")
            # Fallback: Boş döndür
            return []
    
    # ============= METHOD 2: WEB SCRAPING =============
    def get_latest_exploits_scrape(self, limit: int = 30) -> List[Dict]:
        """
        Web scraping ile son exploit'leri çeker
        ⚠ Rate limiting ve robots.txt kurallarına dikkat
        """
        try:
            logger.info("0day.today'den web scraping yapılıyor...")
            
            response = self.session.get(
                f"{self.MAIN_URL}/exploit/",
                timeout=self.timeout
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            exploits = []
            
            # Exploit tablolarını bul
            exploit_items = soup.find_all('tr', class_='post-item')
            
            for item in exploit_items[:limit]:
                try:
                    title_elem = item.find('a', class_='exploit-title')
                    date_elem = item.find('td', class_='post-date')
                    author_elem = item.find('td', class_='post-author')
                    
                    if title_elem:
                        exploit = {
                            'title': title_elem.get_text(strip=True),
                            'url': title_elem.get('href'),
                            'published': date_elem.get_text(strip=True) if date_elem else '',
                            'author': author_elem.get_text(strip=True) if author_elem else '',
                            'source': '0day-today-scrape',
                            'collected_at': datetime.now().isoformat()
                        }
                        exploits.append(exploit)
                except Exception as e:
                    logger.warning(f"Item parse hatası: {e}")
                    continue
            
            logger.info(f"✓ {len(exploits)} exploit scraping'den toplandı")
            return exploits
            
        except Exception as e:
            logger.error(f"Web scraping hatası: {e}")
            return []
    
    # ============= METHOD 3: CATEGORY FILTER =============
    def get_by_category(self, 
                       category: str = 'vulns',
                       limit: int = 20) -> List[Dict]:
        """
        Kategoriye göre exploit'leri çeker
        categories: 'vulns', 'malware', 'source_code', 'tools', 'tutorials'
        """
        try:
            logger.info(f"'{category}' kategorisinden exploit'ler çekiliyor...")
            
            url = f"{self.MAIN_URL}/{category}/"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            exploits = []
            
            items = soup.find_all('div', class_='content-item')
            
            for item in items[:limit]:
                try:
                    title = item.find('h2', class_='title')
                    link = item.find('a', class_='read-more')
                    date = item.find('span', class_='date')
                    
                    if title and link:
                        exploit = {
                            'title': title.get_text(strip=True),
                            'url': link.get('href'),
                            'category': category,
                            'date': date.get_text(strip=True) if date else '',
                            'source': '0day-today-category',
                            'collected_at': datetime.now().isoformat()
                        }
                        exploits.append(exploit)
                except Exception as e:
                    logger.warning(f"Category parse hatası: {e}")
                    continue
            
            logger.info(f"✓ {len(exploits)} '{category}' exploit toplandı")
            return exploits
            
        except Exception as e:
            logger.error(f"Kategori çekme hatası: {e}")
            return []
    
    # ============= METHOD 4: SEARCH =============
    def search_exploits(self, 
                       keyword: str,
                       category: str = None) -> List[Dict]:
        """
        Keyword arama yapma
        """
        try:
            logger.info(f"'{keyword}' için arama yapılıyor...")
            
            params = {
                'q': keyword
            }
            
            if category:
                params['cat'] = category
            
            response = self.session.get(
                f"{self.MAIN_URL}/search/",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            exploits = []
            
            results = soup.find_all('div', class_='search-result')
            
            for result in results:
                try:
                    title_elem = result.find('a', class_='result-title')
                    desc_elem = result.find('p', class_='result-description')
                    
                    if title_elem:
                        exploit = {
                            'title': title_elem.get_text(strip=True),
                            'url': title_elem.get('href'),
                            'description': desc_elem.get_text(strip=True) if desc_elem else '',
                            'keyword': keyword,
                            'source': '0day-today-search',
                            'collected_at': datetime.now().isoformat()
                        }
                        exploits.append(exploit)
                except Exception as e:
                    logger.warning(f"Search result parse hatası: {e}")
                    continue
            
            logger.info(f"✓ {len(exploits)} arama sonucu bulundu")
            return exploits
            
        except Exception as e:
            logger.error(f"Arama hatası: {e}")
            return []
    
    # ============= METHOD 5: DETAIL EXTRACTION =============
    def get_exploit_details(self, exploit_url: str) -> Optional[Dict]:
        """
        Belirli bir exploit'in detaylı bilgisini çeker
        """
        try:
            response = self.session.get(exploit_url, timeout=self.timeout)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Ana bilgiler
            title = soup.find('h1', class_='exploit-title')
            content = soup.find('div', class_='exploit-content')
            author = soup.find('span', class_='author-name')
            date = soup.find('span', class_='publish-date')
            
            # Tehdit seviyesi tayin et
            content_text = content.get_text().lower() if content else ""
            severity = self._extract_severity(content_text)
            
            detail = {
                'title': title.get_text(strip=True) if title else '',
                'url': exploit_url,
                'author': author.get_text(strip=True) if author else '',
                'date': date.get_text(strip=True) if date else '',
                'content': content.get_text(strip=True)[:1000] if content else '',
                'severity': severity,
                'source': '0day-today-detail',
                'collected_at': datetime.now().isoformat()
            }
            
            logger.info(f"✓ Detail çekildi: {title.get_text(strip=True) if title else 'Unknown'}")
            return detail
            
        except Exception as e:
            logger.error(f"Detail çekme hatası: {e}")
            return None
    
    # ============= HELPER FUNCTIONS =============
    def _extract_severity(self, content: str) -> str:
        """
        İçerikten tehdit seviyesini çıkart
        """
        content_lower = content.lower()
        
        if any(word in content_lower for word in ['critical', 'kritik', 'rce', 'remote code']):
            return 'CRITICAL'
        elif any(word in content_lower for word in ['high', 'yüksek', 'sql injection', 'xss']):
            return 'HIGH'
        elif any(word in content_lower for word in ['medium', 'orta', 'medium']):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_trending_exploits(self, limit: int = 10) -> List[Dict]:
        """
        Trending exploit'leri al
        """
        try:
            logger.info("Trending exploit'ler çekiliyor...")
            
            response = self.session.get(
                f"{self.MAIN_URL}/trending/",
                timeout=self.timeout
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            exploits = []
            
            trends = soup.find_all('div', class_='trending-item')[:limit]
            
            for trend in trends:
                try:
                    title = trend.find('a', class_='trend-title')
                    views = trend.find('span', class_='view-count')
                    
                    if title:
                        exploit = {
                            'title': title.get_text(strip=True),
                            'url': title.get('href'),
                            'views': views.get_text(strip=True) if views else '0',
                            'source': '0day-today-trending',
                            'collected_at': datetime.now().isoformat()
                        }
                        exploits.append(exploit)
                except Exception as e:
                    logger.warning(f"Trending parse hatası: {e}")
                    continue
            
            logger.info(f"✓ {len(exploits)} trending exploit bulundu")
            return exploits
            
        except Exception as e:
            logger.error(f"Trending çekme hatası: {e}")
            return []


# ============= KULLANIM ÖRNEĞİ =============
if __name__ == "__main__":
    collector = ZeroDayTodayCollector()
    
    # RSS Feed'den son zero-days
    print("\n=== RSS Feed'den Son 5 Zero-Day ===")
    rss_exploits = collector.get_latest_from_rss(limit=5)
    for exploit in rss_exploits[:3]:
        print(f"- [{exploit['severity']}] {exploit['title'][:50]}")
        print(f"  URL: {exploit['url']}")
    
    # Kategoriye göre çekme
    print("\n=== Vulnerability Kategorisinden ===")
    vulns = collector.get_by_category('vulns', limit=5)
    for exploit in vulns[:3]:
        print(f"- {exploit['title'][:50]}")
    
    # Arama yapma
    print("\n=== 'Apache' Arama ===")
    search_results = collector.search_exploits("Apache", limit=5)
    for exploit in search_results[:3]:
        print(f"- {exploit['title'][:50]}")
    
    # Trending exploit'ler
    print("\n=== Trending Exploit'ler ===")
    trending = collector.get_trending_exploits(limit=5)
    for exploit in trending:
        print(f"- {exploit['title'][:50]} (Views: {exploit['views']})")
