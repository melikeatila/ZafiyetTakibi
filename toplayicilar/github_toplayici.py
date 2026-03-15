import os
import re
import sys
import unicodedata
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import requests
from github import Github
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from veritabani.baglanti import session_al
from modeller.zafiyet import Zafiyet, OnemDerecesi, ZafiyetDurumu

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class GithubToplayici:
    def __init__(self):
        if not GITHUB_TOKEN:
            raise ValueError("GITHUB_TOKEN .env içinde tanımlı olmalı.")

        self.github = Github(GITHUB_TOKEN, per_page=30)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"token {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def _ozel_karakter_temizle(self, text):
        if text is None:
            return None
        text = unicodedata.normalize("NFKC", str(text))
        text = text.replace("\x00", " ").replace("\r", " ")
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _guvenli_text(self, value, limit=2000):
        if value is None:
            return None
        temiz = self._ozel_karakter_temizle(value)
        return temiz[:limit] if temiz else None

    def _zorunlu_aciklama(self, aciklama, baslik=""):
        temiz = self._guvenli_text(aciklama, 2000)
        if temiz:
            return temiz

        temiz_baslik = self._guvenli_text(baslik, 300) or "Başlıksız kayıt"
        return f"Açıklama bulunamadı. Başlık: {temiz_baslik}"

    def _repo_adi_coz(self, repository_url):
        if not repository_url:
            return None
        try:
            parsed = urlparse(repository_url)
            path = parsed.path.strip("/")
            if path.startswith("repos/"):
                return path.replace("repos/", "", 1)
            return path or None
        except Exception:
            return None

    def _str_to_enum(self, deger):
        if not deger:
            return None
        try:
            return OnemDerecesi[deger.upper()]
        except Exception:
            return None

    def _baslangic_tarihi_hesapla(self, saat=None, gun=7):
        if saat is None:
            saat = gun * 24
        return datetime.now(timezone.utc) - timedelta(hours=saat)

    def security_advisories_al(self, saat=None, gun=7):
        print("Security Advisories taranıyor...")
        veriler = []
        baslangic_tarihi = self._baslangic_tarihi_hesapla(saat=saat, gun=gun)

        try:
            query = """
            query($first: Int!) {
              securityAdvisories(first: $first, orderBy: {field: UPDATED_AT, direction: DESC}) {
                nodes {
                  ghsaId
                  summary
                  description
                  severity
                  publishedAt
                  updatedAt
                  references {
                    url
                  }
                  identifiers {
                    type
                    value
                  }
                  vulnerabilities(first: 10) {
                    nodes {
                      package {
                        name
                      }
                    }
                  }
                }
              }
            }
            """

            response = self.session.post(
                "https://api.github.com/graphql",
                json={"query": query, "variables": {"first": 30}},
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()

            advisories = (
                data.get("data", {})
                .get("securityAdvisories", {})
                .get("nodes", [])
            )

            for advisory in advisories:
                try:
                    tarih = advisory.get("publishedAt") or advisory.get("updatedAt")
                    bulunan_tarih = datetime.now(timezone.utc)
                    if tarih:
                        bulunan_tarih = datetime.fromisoformat(tarih.replace("Z", "+00:00"))

                    if bulunan_tarih < baslangic_tarihi:
                        continue

                    identifiers = advisory.get("identifiers", []) or []
                    cve = None
                    for item in identifiers:
                        if item.get("type") == "CVE" and item.get("value"):
                            cve = item["value"].upper()
                            break

                    refs = advisory.get("references", []) or []
                    url = refs[0]["url"] if refs and refs[0].get("url") else None

                    paketler = []
                    vulnerabilities = advisory.get("vulnerabilities", {}).get("nodes", []) or []
                    for v in vulnerabilities:
                        paket_adi = ((v or {}).get("package") or {}).get("name")
                        if paket_adi:
                            paketler.append(paket_adi)

                    baslik = (
                        self._guvenli_text(advisory.get("summary"), 300)
                        or advisory.get("ghsaId")
                        or "GitHub Security Advisory"
                    )

                    veri = {
                        "baslik": baslik,
                        "aciklama": self._zorunlu_aciklama(advisory.get("description"), baslik),
                        "kaynak": "GitHub",
                        "url": url,
                        "bulunan_tarih": bulunan_tarih,
                        "cve_numarasi": cve,
                        "kategori": "GitHub Security Advisory",
                        "etkilenen_yazilimlar": ", ".join(paketler[:10]) if paketler else None,
                        "onem_derecesi": None,
                    }
                    veriler.append(veri)
                except Exception as inner_e:
                    print(f"Advisory işlenemedi: {inner_e}")
                    continue

            print(f"Security Advisories: {len(veriler)} sonuç")
        except Exception as e:
            print(f"GitHub Security Advisories alınırken hata: {e}")

        return veriler

    def cve_issues_al(self, saat=None, gun=7):
        print("CVE issue'ları taranıyor...")
        veriler = []
        baslangic_tarihi = self._baslangic_tarihi_hesapla(saat=saat, gun=gun)

        try:
            tarih_str = baslangic_tarihi.strftime("%Y-%m-%dT%H:%M:%SZ")
            query = f"CVE in:title,body type:issue created:>={tarih_str}"
            issues = self.github.search_issues(query, sort="updated", order="desc")

            max_kayit = 30
            for i, issue in enumerate(issues):
                if i >= max_kayit:
                    break

                try:
                    baslik = self._guvenli_text(getattr(issue, "title", None), 300) or "GitHub CVE Issue"
                    aciklama = self._zorunlu_aciklama(getattr(issue, "body", None), baslik)
                    url = getattr(issue, "html_url", None)

                    raw_data = getattr(issue, "raw_data", {}) or {}
                    repository_url = raw_data.get("repository_url")
                    repo_adi = self._repo_adi_coz(repository_url)

                    created_at = getattr(issue, "created_at", None)
                    if created_at and created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)

                    cve_match = CVE_PATTERN.search(f"{baslik} {aciklama}")
                    cve = cve_match.group(0).upper() if cve_match else None

                    veri = {
                        "baslik": baslik,
                        "aciklama": aciklama,
                        "kaynak": "GitHub",
                        "url": url,
                        "bulunan_tarih": created_at or datetime.now(timezone.utc),
                        "cve_numarasi": cve,
                        "kategori": "GitHub CVE Issue",
                        "etkilenen_yazilimlar": repo_adi,
                        "onem_derecesi": None,
                    }
                    veriler.append(veri)
                except Exception as inner_e:
                    print(f"Issue işlenemedi: {inner_e}")
                    continue

            print(f"CVE Issues: {len(veriler)} sonuç")
        except Exception as e:
            print(f"GitHub CVE Issues alınırken hata: {e}")

        return veriler

    def vulnerability_repos_al(self, saat=None, gun=7):
        print("Vulnerability reposları taranıyor...")
        veriler = []
        baslangic_tarihi = self._baslangic_tarihi_hesapla(saat=saat, gun=gun)

        try:
            keywords = ["vulnerability", "exploit", "zero-day"]
            tarih_str = baslangic_tarihi.strftime("%Y-%m-%dT%H:%M:%SZ")
            max_per_keyword = 10

            for keyword in keywords:
                query = f"{keyword} in:name,description pushed:>={tarih_str}"
                repos = self.github.search_repositories(query=query, sort="updated", order="desc")

                for i, repo in enumerate(repos):
                    if i >= max_per_keyword:
                        break

                    try:
                        pushed_at = getattr(repo, "pushed_at", None)
                        if pushed_at and pushed_at.tzinfo is None:
                            pushed_at = pushed_at.replace(tzinfo=timezone.utc)

                        baslik = self._guvenli_text(getattr(repo, "full_name", None), 300) or "GitHub Repository"

                        veri = {
                            "baslik": baslik,
                            "aciklama": self._zorunlu_aciklama(getattr(repo, "description", None), baslik),
                            "kaynak": "GitHub",
                            "url": getattr(repo, "html_url", None),
                            "bulunan_tarih": pushed_at or datetime.now(timezone.utc),
                            "cve_numarasi": None,
                            "kategori": f"GitHub Repo ({keyword})",
                            "etkilenen_yazilimlar": getattr(repo, "full_name", None),
                            "onem_derecesi": None,
                        }
                        veriler.append(veri)
                    except Exception as inner_e:
                        print(f"Repo işlenemedi: {inner_e}")
                        continue

            print(f"Vulnerability Repos: {len(veriler)} sonuç")
        except Exception as e:
            print(f"GitHub Vulnerability Repos alınırken hata: {e}")

        return veriler

    def veritabanina_kaydet(self, veriler):
        if not veriler:
            return 0

        db = session_al()
        yeni = 0
        try:
            durum_default = getattr(ZafiyetDurumu, "YENI", None)

            for v in veriler:
                url = (v.get("url") or "").strip()
                baslik = (v.get("baslik") or "").strip()
                aciklama = self._zorunlu_aciklama(v.get("aciklama"), baslik)

                mevcut = None
                if url:
                    mevcut = db.query(Zafiyet).filter(Zafiyet.url == url).first()

                if mevcut is None and baslik:
                    mevcut = db.query(Zafiyet).filter(
                        Zafiyet.kaynak == "GitHub",
                        Zafiyet.baslik == baslik
                    ).first()

                if mevcut:
                    continue

                z = Zafiyet(
                    baslik=baslik or "Başlıksız GitHub Kaydı",
                    aciklama=aciklama,
                    kaynak="GitHub",
                    url=url or None,
                    bulunan_tarih=v.get("bulunan_tarih") or datetime.now(timezone.utc),
                    cve_numarasi=v.get("cve_numarasi"),
                    kategori=v.get("kategori"),
                    etkilenen_yazilimlar=v.get("etkilenen_yazilimlar"),
                    onem_derecesi=None,
                    durum=durum_default,
                )
                db.add(z)
                yeni += 1
                print(f"Yeni kayit: {(baslik or 'Başlıksız')[:60]}...")

            db.commit()
            print(f"\n{yeni} yeni kayit eklendi (duplicate'ler atlandi)")
            return yeni
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def tum_verileri_topla(self, saat=None, gun=7):
        print("\nGitHub verileri toplanıyor...")
        tum_veriler = []
        tum_veriler.extend(self.security_advisories_al(saat=saat, gun=gun))
        tum_veriler.extend(self.cve_issues_al(saat=saat, gun=gun))
        tum_veriler.extend(self.vulnerability_repos_al(saat=saat, gun=gun))
        return tum_veriler


if __name__ == "__main__":
    toplayici = GithubToplayici()
    veriler = toplayici.tum_verileri_topla(saat=6)
    print(f"\nToplam {len(veriler)} veri bulundu")

    if veriler:
        yeni_kayit = toplayici.veritabanina_kaydet(veriler)
        print(f"\n{yeni_kayit} yeni kayıt veritabanına eklendi")