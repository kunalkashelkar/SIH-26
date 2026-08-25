import urllib.parse

def is_valid_url(url: str) -> bool:
    if not url:
        return False
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in ("http", "https")

def normalize_url(url: str, base_url: str) -> str:
    """Resolves relative links and removes fragments."""
    if not url:
        return ""
        
    # Handle base resolution for relative links
    joined = urllib.parse.urljoin(base_url, url)
    
    # Parse to strip fragments
    parsed = urllib.parse.urlparse(joined)
    
    # Reconstruct without fragment
    normalized = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        "" # fragment
    ))
    return normalized

def is_in_scope(url: str, target_base_url: str) -> bool:
    """Checks if the URL is within the target's scope (same domain/subdomain depending on rules). For prototype, exact netloc match."""
    if not is_valid_url(url):
        return False
        
    target_parsed = urllib.parse.urlparse(target_base_url)
    url_parsed = urllib.parse.urlparse(url)
    
    # We restrict to exactly the same netloc (host:port) for the prototype
    return target_parsed.netloc == url_parsed.netloc
