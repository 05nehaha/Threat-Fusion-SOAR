import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_website(target, max_links=15):
    """
    Simple & safe crawler:
    - Bypasses bot filters using User-Agent
    - Handles http/https and redirects
    - Extracts links and forms within the same domain OR subdomains
    """

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    # --- THE KEY FIX: Browser Identity ---
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
    }

    crawled_urls = set()

    try:
        # Pass the headers into the get request
        response = requests.get(
            target,
            headers=headers, 
            timeout=10,
            allow_redirects=True
        )

        # If the server blocks us (403), we can't crawl
        if response.status_code != 200:
            print(f"[Crawler] Access Denied (Status {response.status_code})")
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        
        # Get the "base" domain (e.g. "toscrape.com") to compare against
        base_netloc = urlparse(response.url).netloc
        
        # 🔗 Extract anchor links
        for link in soup.find_all("a", href=True):
            full_url = urljoin(response.url, link["href"])
            parsed = urlparse(full_url)

            # FIX: Allow exact match OR subdomains (e.g. books.toscrape.com)
            if parsed.netloc == base_netloc or parsed.netloc.endswith("." + base_netloc):
                crawled_urls.add(full_url)

            if len(crawled_urls) >= max_links:
                break

        # 🧾 Extract forms
        for form in soup.find_all("form", action=True):
            form_url = urljoin(response.url, form["action"])
            parsed = urlparse(form_url)

            # FIX: Apply same logic to forms
            if parsed.netloc == base_netloc or parsed.netloc.endswith("." + base_netloc):
                crawled_urls.add(f"[FORM] {form_url}")

            if len(crawled_urls) >= max_links:
                break

    except Exception as e:
        print(f"[Crawler] Error: {e}")

    return list(crawled_urls)