import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import time
from typing import Dict, Any, List
from datetime import datetime

import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from core.database import AsyncSessionLocal
from models.models import Scan, Finding, Endpoint

class ScannerEngine:
    def __init__(self, scan_id: str, target_url: str, request_limit: int, crawl_depth: int):
        self.scan_id = scan_id
        self.target_url = target_url
        self.request_limit = request_limit
        self.crawl_depth = crawl_depth
        self.base_domain = urlparse(target_url).netloc
        
        self.visited_urls = set()
        self.urls_to_visit = [(target_url, 0)] # (url, depth)
        self.logs: List[str] = []
        self.findings: List[Dict[str, str]] = []
        
        self.request_count = 0
        self.status = "Initializing"
        self.is_running = True
        self.progress = 0
        self.start_time = time.time()
        
    def log(self, message: str, level: str = "INFO"):
        self.logs.append(f"[{level}] {message}")
        print(f"[{self.scan_id}] [{level}] {message}")

    async def scan(self):
        self.status = "Running"
        self.log(f"Initializing scan for target: {self.target_url}", "INFO")
        self.log("Starting asset discovery phase...", "INFO")
        
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            while self.urls_to_visit and self.is_running and self.request_count < self.request_limit:
                current_url, current_depth = self.urls_to_visit.pop(0)
                
                if current_url in self.visited_urls:
                    continue
                    
                self.visited_urls.add(current_url)
                
                if current_depth > self.crawl_depth:
                    continue

                self.request_count += 1
                self.log(f"Scanning endpoint: {current_url}", "DEBUG")
                
                try:
                    response = await client.get(current_url)
                    self.analyze_response(response, current_url)
                    
                    if "text/html" in response.headers.get("Content-Type", ""):
                        self.extract_links(response.text, current_url, current_depth)
                
                except Exception as e:
                    self.log(f"Error scanning {current_url}: {str(e)}", "WARN")
                    
                # Rate limiting (e.g. 5 requests per second max)
                await asyncio.sleep(0.2)
                
                # Update progress roughly based on queue size vs visited (heuristic) or just rely on a slow crawl
                total_known = len(self.visited_urls) + len(self.urls_to_visit)
                if total_known > 0:
                    self.progress = int((len(self.visited_urls) / total_known) * 100)
                
        if self.is_running:
            self.status = "Completed"
            self.progress = 100
            self.log("Scan completed successfully.", "SUCCESS")
        else:
            self.status = "Cancelled"
            self.log("Scan was cancelled by user.", "WARN")
            
        # Update Scan in DB
        async with AsyncSessionLocal() as session:
            db_scan = await session.get(Scan, self.scan_id)
            if db_scan:
                db_scan.status = self.status
                db_scan.progress = self.progress
                db_scan.end_time = datetime.utcnow()
                await session.commit()

    def analyze_response(self, response: httpx.Response, url: str):
        headers = response.headers
        
        # Check security headers
        missing_headers = []
        if "Strict-Transport-Security" not in headers:
            missing_headers.append("Strict-Transport-Security")
        if "X-Content-Type-Options" not in headers:
            missing_headers.append("X-Content-Type-Options")
        if "X-Frame-Options" not in headers:
            missing_headers.append("X-Frame-Options")
            
        if missing_headers:
            finding = {
                "url": url,
                "type": "Missing Security Headers",
                "severity": "Low",
                "description": f"Missing headers: {', '.join(missing_headers)}"
            }
            self.findings.append(finding)
            asyncio.create_task(self.save_finding(finding))
            if len(self.findings) <= 5: # Limit log spam
                self.log(f"Missing security headers on {url}", "ALERT")
                
        if response.status_code == 200 and "admin" in url.lower():
             finding = {
                "url": url,
                "type": "Exposed Admin Panel",
                "severity": "High",
                "description": f"Potential admin panel exposed."
             }
             self.findings.append(finding)
             asyncio.create_task(self.save_finding(finding))
             self.log(f"Found unauthenticated admin panel at {url}", "SUCCESS")

        # Save Endpoint to DB
        asyncio.create_task(self.save_endpoint(url, response.request.method, response.status_code))

    async def save_finding(self, finding_dict: dict):
        async with AsyncSessionLocal() as session:
            db_finding = Finding(
                scan_id=self.scan_id,
                type=finding_dict["type"],
                severity=finding_dict["severity"],
                url=finding_dict["url"],
                description=finding_dict["description"]
            )
            session.add(db_finding)
            await session.commit()
            
    async def save_endpoint(self, url: str, method: str, status_code: int):
        async with AsyncSessionLocal() as session:
            db_ep = Endpoint(
                scan_id=self.scan_id,
                method=method,
                url=url,
                status_code=status_code
            )
            session.add(db_ep)
            await session.commit()


    def extract_links(self, html: str, base_url: str, current_depth: int):
        soup = BeautifulSoup(html, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            parsed_url = urlparse(full_url)
            
            # Scope validation
            if parsed_url.netloc == self.base_domain or parsed_url.netloc.endswith("." + self.base_domain):
                # Normalize URL (remove fragment)
                full_url = full_url.split('#')[0]
                if full_url not in self.visited_urls:
                    self.urls_to_visit.append((full_url, current_depth + 1))
                    
    def cancel(self):
        self.is_running = False
        self.status = "Cancelling..."
