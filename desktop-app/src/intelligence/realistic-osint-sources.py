#!/usr/bin/env python3
"""
============================================================================
APOLLOSENTINEL™ REALISTIC OSINT SOURCES - PRODUCTION READY
Real, accessible intelligence sources without simulation
============================================================================
"""

import asyncio
import aiohttp
import json
import os
import time
import hashlib
import base64
import logging
import re
import feedparser
from typing import Dict, List, Optional, Any, Union
from urllib.parse import quote, urlencode
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class SourceCategory(Enum):
    THREAT_INTELLIGENCE = "threat_intelligence"
    DOMAIN_DNS = "domain_dns"
    CERTIFICATES = "certificates"
    REPUTATION = "reputation"
    VULNERABILITY = "vulnerability"
    FEEDS = "feeds"
    PUBLIC_RECORDS = "public_records"
    ARCHIVES = "archives"
    SOCIAL_MEDIA = "social_media"
    FINANCIAL_CRYPTO = "financial_crypto"
    COMMUNICATION = "communication"

@dataclass
class RealOSINTSource:
    """Represents a real, accessible OSINT intelligence source"""
    name: str
    category: SourceCategory
    base_url: str
    api_key_env: Optional[str] = None
    requires_auth: bool = False
    rate_limit: int = 100  # requests per hour
    reliability_score: float = 0.8  # 0.0 to 1.0
    data_types: List[str] = None
    description: str = ""
    free_tier: bool = True
    
    def __post_init__(self):
        if self.data_types is None:
            self.data_types = []

class RealisticOSINTManager:
    """Manages real, accessible OSINT intelligence sources"""
    
    def __init__(self):
        self.session = None
        self.sources = self._initialize_real_sources()
        self.rate_limiters = {}
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'ApolloSentinel OSINT Platform v2.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _initialize_real_sources(self) -> Dict[str, RealOSINTSource]:
        """Initialize real, accessible OSINT sources"""
        sources = {}
        
        # ============================================================================
        # FREE/OPEN THREAT INTELLIGENCE SOURCES
        # ============================================================================
        
        threat_sources = [
            # User's Premium API Sources
            RealOSINTSource(
                "AlienVault OTX", SourceCategory.THREAT_INTELLIGENCE,
                "https://otx.alienvault.com/api/v1",
                api_key_env="ALIENVAULT_OTX_API_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.95,
                data_types=["threats", "malware", "iocs", "pulses"],
                description="Premium threat intelligence from AlienVault OTX (User's API Key)"
            ),
            
            RealOSINTSource(
                "ThreatCrowd", SourceCategory.THREAT_INTELLIGENCE,
                "https://www.threatcrowd.org/searchApi/v2",
                requires_auth=False, free_tier=True,
                reliability_score=0.85, 
                data_types=["domains", "ips", "malware", "hashes"],
                description="Free threat intelligence search engine"
            ),
            
            RealOSINTSource(
                "URLVoid", SourceCategory.REPUTATION,
                "http://api.urlvoid.com/v1",
                requires_auth=False, free_tier=True,
                reliability_score=0.80,
                data_types=["url_reputation", "domain_analysis"],
                description="Free URL and domain reputation checker"
            ),
            
            RealOSINTSource(
                "AbuseIPDB", SourceCategory.REPUTATION,
                "https://api.abuseipdb.com/v2",
                api_key_env="ABUSEIPDB_API_KEY", requires_auth=True, free_tier=True,
                reliability_score=0.90,
                data_types=["ip_reputation", "abuse_reports"],
                description="IP address abuse database (free tier: 1000 requests/day)"
            ),
            
            RealOSINTSource(
                "Malware Bazaar", SourceCategory.THREAT_INTELLIGENCE,
                "https://mb-api.abuse.ch/api/v1",
                requires_auth=False, free_tier=True,
                reliability_score=0.92,
                data_types=["malware", "samples", "families", "hashes"],
                description="Free malware sample database by abuse.ch"
            ),
            
            RealOSINTSource(
                "URLhaus", SourceCategory.THREAT_INTELLIGENCE,
                "https://urlhaus-api.abuse.ch/v1",
                requires_auth=False, free_tier=True,
                reliability_score=0.90,
                data_types=["malicious_urls", "payloads", "signatures"],
                description="Free malicious URL database by abuse.ch"
            ),
            
            RealOSINTSource(
                "ThreatFox", SourceCategory.THREAT_INTELLIGENCE,
                "https://threatfox-api.abuse.ch/api/v1",
                requires_auth=False, free_tier=True,
                reliability_score=0.88,
                data_types=["iocs", "threat_indicators", "malware"],
                description="Free IOC database by abuse.ch"
            ),
            
            RealOSINTSource(
                "Feodo Tracker", SourceCategory.THREAT_INTELLIGENCE,
                "https://feodotracker.abuse.ch/api/v1",
                requires_auth=False, free_tier=True,
                reliability_score=0.90,
                data_types=["botnet", "c2", "malware"],
                description="Free botnet C2 tracker by abuse.ch"
            ),
            
            RealOSINTSource(
                "SSL Blacklist", SourceCategory.THREAT_INTELLIGENCE,
                "https://sslbl.abuse.ch/api/v1",
                requires_auth=False, free_tier=True,
                reliability_score=0.87,
                data_types=["ssl", "certificates", "malware"],
                description="Free malicious SSL certificate blacklist by abuse.ch"
            ),
        ]
        
        # ============================================================================
        # FREE DOMAIN & DNS SOURCES
        # ============================================================================
        
        domain_sources = [
            # User's Premium API Sources
            RealOSINTSource(
                "DNSDumpster", SourceCategory.DOMAIN_DNS,
                "https://dnsdumpster.com/api",
                api_key_env="DNSDUMPSTER_API_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.90,
                data_types=["subdomains", "dns_records", "network_mapping"],
                description="Premium DNS reconnaissance (User's API Key)"
            ),
            
            RealOSINTSource(
                "crt.sh", SourceCategory.CERTIFICATES,
                "https://crt.sh",
                requires_auth=False, free_tier=True,
                reliability_score=0.95,
                data_types=["certificates", "domains", "subdomains"],
                description="Free SSL certificate transparency logs"
            ),
            
            RealOSINTSource(
                "DNS over HTTPS", SourceCategory.DOMAIN_DNS,
                "https://dns.google/resolve",
                requires_auth=False, free_tier=True,
                reliability_score=0.98,
                data_types=["dns_records", "domain_resolution"],
                description="Google DNS over HTTPS service"
            ),
            
            RealOSINTSource(
                "Cloudflare DNS", SourceCategory.DOMAIN_DNS,
                "https://cloudflare-dns.com/dns-query",
                requires_auth=False, free_tier=True,
                reliability_score=0.97,
                data_types=["dns_records", "domain_resolution"],
                description="Cloudflare DNS over HTTPS service"
            ),
            
            RealOSINTSource(
                "DNS Dumpster", SourceCategory.DOMAIN_DNS,
                "https://dnsdumpster.com",
                requires_auth=False, free_tier=True,
                reliability_score=0.85,
                data_types=["subdomains", "dns_records", "network_mapping"],
                description="Free domain research tool (web scraping)"
            ),
        ]
        
        # ============================================================================
        # SOCIAL MEDIA & CONTENT SOURCES (USER'S API KEYS)
        # ============================================================================
        
        social_sources = [
            RealOSINTSource(
                "Reddit", SourceCategory.SOCIAL_MEDIA,
                "https://oauth.reddit.com",
                api_key_env="REDDIT_API_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.85,
                data_types=["posts", "users", "communities", "comments"],
                description="Reddit API access (User's API Key)"
            ),
            
            RealOSINTSource(
                "GitHub", SourceCategory.SOCIAL_MEDIA,
                "https://api.github.com",
                api_key_env="GITHUB_API_TOKEN", requires_auth=True, free_tier=False,
                reliability_score=0.92,
                data_types=["repositories", "users", "commits", "issues"],
                description="GitHub API access (User's API Key)"
            ),
            
            RealOSINTSource(
                "YouTube", SourceCategory.SOCIAL_MEDIA,
                "https://www.googleapis.com/youtube/v3",
                api_key_env="YOUTUBE_API_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.88,
                data_types=["videos", "channels", "comments", "playlists"],
                description="YouTube Data API (User's API Key)"
            ),
        ]
        
        # ============================================================================
        # FINANCIAL & CRYPTO SOURCES (USER'S API KEYS)
        # ============================================================================
        
        financial_sources = [
            RealOSINTSource(
                "CoinGecko", SourceCategory.FINANCIAL_CRYPTO,
                "https://api.coingecko.com/api/v3",
                api_key_env="COINGECKO_API_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.94,
                data_types=["crypto", "prices", "market", "coins"],
                description="CoinGecko Pro API (User's API Key)"
            ),
            
            RealOSINTSource(
                "Etherscan", SourceCategory.FINANCIAL_CRYPTO,
                "https://api.etherscan.io/api",
                api_key_env="ETHERSCAN_API_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.96,
                data_types=["ethereum", "transactions", "addresses", "contracts"],
                description="Etherscan API (User's API Key)"
            ),
        ]
        
        # ============================================================================
        # NEWS & COMMUNICATION SOURCES (USER'S API KEYS)
        # ============================================================================
        
        news_comm_sources = [
            RealOSINTSource(
                "NewsAPI", SourceCategory.FEEDS,
                "https://newsapi.org/v2",
                api_key_env="NEWSAPI_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.90,
                data_types=["news", "articles", "headlines", "sources"],
                description="NewsAPI access (User's API Key)"
            ),
            
            RealOSINTSource(
                "Hunter.io", SourceCategory.COMMUNICATION,
                "https://api.hunter.io/v2",
                api_key_env="HUNTER_IO_API_KEY", requires_auth=True, free_tier=False,
                reliability_score=0.91,
                data_types=["emails", "domains", "verification", "leads"],
                description="Hunter.io API (User's API Key)"
            ),
            
            RealOSINTSource(
                "TruthFinder", SourceCategory.PUBLIC_RECORDS,
                "https://www.truthfinder.com/api",
                api_key_env="TRUTHFINDER_ACCOUNT_ID", requires_auth=True, free_tier=False,
                reliability_score=0.87,
                data_types=["background_checks", "contact_info", "address_history"],
                description="TruthFinder API (User's Account: 26676, Member: 212900365)"
            ),
        ]

        # ============================================================================
        # FREE GEOLOCATION SOURCES
        # ============================================================================
        
        geo_sources = [
            RealOSINTSource(
                "ip-api.com", SourceCategory.PUBLIC_RECORDS,
                "http://ip-api.com/json",
                requires_auth=False, free_tier=True,
                reliability_score=0.85,
                data_types=["geolocation", "isp", "organization"],
                description="Free IP geolocation service (1000 requests/hour)"
            ),
            
            RealOSINTSource(
                "ipapi.co", SourceCategory.PUBLIC_RECORDS,
                "https://ipapi.co",
                requires_auth=False, free_tier=True,
                reliability_score=0.82,
                data_types=["geolocation", "asn", "carrier"],
                description="Free IP geolocation API (1000 requests/day)"
            ),
            
            RealOSINTSource(
                "freegeoip.app", SourceCategory.PUBLIC_RECORDS,
                "https://freegeoip.app/json",
                requires_auth=False, free_tier=True,
                reliability_score=0.80,
                data_types=["geolocation", "timezone", "country"],
                description="Free IP geolocation service"
            ),
        ]
        
        # ============================================================================
        # FREE ARCHIVE SOURCES
        # ============================================================================
        
        archive_sources = [
            RealOSINTSource(
                "Wayback Machine", SourceCategory.ARCHIVES,
                "https://web.archive.org/wayback/available",
                requires_auth=False, free_tier=True,
                reliability_score=0.95,
                data_types=["archived_pages", "historical_data", "snapshots"],
                description="Internet Archive Wayback Machine"
            ),
            
            RealOSINTSource(
                "Archive.today", SourceCategory.ARCHIVES,
                "https://archive.today",
                requires_auth=False, free_tier=True,
                reliability_score=0.88,
                data_types=["page_archives", "snapshots"],
                description="Free webpage archiving service"
            ),
        ]
        
        # ============================================================================
        # RSS/FEED SOURCES
        # ============================================================================
        
        feed_sources = [
            RealOSINTSource(
                "CISA Alerts", SourceCategory.FEEDS,
                "https://www.cisa.gov/uscert/ncas/alerts.xml",
                requires_auth=False, free_tier=True,
                reliability_score=0.98,
                data_types=["security_alerts", "advisories", "vulnerabilities"],
                description="CISA cybersecurity alerts RSS feed"
            ),
            
            RealOSINTSource(
                "US-CERT Alerts", SourceCategory.FEEDS,
                "https://www.us-cert.gov/ncas/alerts.xml",
                requires_auth=False, free_tier=True,
                reliability_score=0.95,
                data_types=["security_alerts", "threat_advisories"],
                description="US-CERT security alerts RSS feed"
            ),
            
            RealOSINTSource(
                "SANS Internet Storm Center", SourceCategory.FEEDS,
                "https://isc.sans.edu/rssfeed.xml",
                requires_auth=False, free_tier=True,
                reliability_score=0.90,
                data_types=["threat_intelligence", "security_diary"],
                description="SANS ISC daily security diary RSS feed"
            ),
            
            RealOSINTSource(
                "Krebs on Security", SourceCategory.FEEDS,
                "https://krebsonsecurity.com/feed/",
                requires_auth=False, free_tier=True,
                reliability_score=0.85,
                data_types=["security_news", "breach_reports", "investigations"],
                description="Security journalism and investigations RSS feed"
            ),
        ]
        
        # ============================================================================
        # VULNERABILITY SOURCES
        # ============================================================================
        
        vuln_sources = [
            RealOSINTSource(
                "CVE Details", SourceCategory.VULNERABILITY,
                "https://www.cvedetails.com",
                requires_auth=False, free_tier=True,
                reliability_score=0.92,
                data_types=["vulnerabilities", "cve_data", "vendor_info"],
                description="Free CVE vulnerability database"
            ),
            
            RealOSINTSource(
                "NVD NIST", SourceCategory.VULNERABILITY,
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                requires_auth=False, free_tier=True,
                reliability_score=0.98,
                data_types=["cve_data", "cvss_scores", "vulnerability_details"],
                description="NIST National Vulnerability Database API"
            ),
            
            RealOSINTSource(
                "CVE Details", SourceCategory.VULNERABILITY,
                "https://www.cvedetails.com/api",
                requires_auth=False, free_tier=True,
                reliability_score=0.92,
                data_types=["vulnerabilities", "cve_data", "vendor_info"],
                description="Free CVE vulnerability database"
            ),
            
            RealOSINTSource(
                "Exploit Database", SourceCategory.VULNERABILITY,
                "https://www.exploit-db.com/api",
                requires_auth=False, free_tier=True,
                reliability_score=0.89,
                data_types=["exploits", "vulnerabilities", "proof_of_concept"],
                description="Free exploit database by Offensive Security"
            ),
        ]
        
        # ============================================================================
        # FREEMIUM SOURCES (Free tier available)
        # ============================================================================
        
        freemium_sources = [
            RealOSINTSource(
                "VirusTotal", SourceCategory.THREAT_INTELLIGENCE,
                "https://www.virustotal.com/vtapi/v2",
                api_key_env="VIRUSTOTAL_API_KEY", requires_auth=True, free_tier=True,
                reliability_score=0.98,
                data_types=["malware", "files", "urls", "domains"],
                description="Free tier: 4 requests/minute, 500/day"
            ),
            
            RealOSINTSource(
                "Shodan", SourceCategory.DOMAIN_DNS,
                "https://api.shodan.io",
                api_key_env="SHODAN_API_KEY", requires_auth=True, free_tier=True,
                reliability_score=0.94,
                data_types=["hosts", "services", "banners", "vulnerabilities"],
                description="Free tier: 100 results/month"
            ),
            
            RealOSINTSource(
                "Have I Been Pwned", SourceCategory.REPUTATION,
                "https://haveibeenpwned.com/api/v3",
                api_key_env="HIBP_API_KEY", requires_auth=True, free_tier=True,
                reliability_score=0.96,
                data_types=["breaches", "emails", "passwords"],
                description="Free for non-commercial use"
            ),
        ]
        
        # Combine all sources
        all_source_lists = [
            threat_sources, domain_sources, social_sources, financial_sources,
            news_comm_sources, geo_sources, archive_sources, feed_sources, 
            vuln_sources, freemium_sources
        ]
        
        for source_list in all_source_lists:
            for source in source_list:
                sources[source.name] = source
        
        logger.info(f"✅ Initialized {len(sources)} real OSINT sources")
        return sources
    
    # ============================================================================
    # REAL DATA QUERY IMPLEMENTATIONS (INCLUDING USER'S API KEYS)
    # ============================================================================
    
    async def query_alienvault_otx(self, indicator: str, indicator_type: str = 'domain') -> Dict[str, Any]:
        """Query AlienVault OTX using user's API key"""
        try:
            api_key = os.getenv('ALIENVAULT_OTX_API_KEY', '762c4e5345c0c5b61c5896bc0e4de2a7fc52fc930b2209e5478c5367d646a777')
            url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
            headers = {'X-OTX-API-KEY': api_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'AlienVault OTX (User API)',
                        'indicator': indicator,
                        'reputation': data.get('reputation', 0),
                        'pulse_count': len(data.get('pulse_info', {}).get('pulses', [])),
                        'malware_families': data.get('malware', {}).get('data', []),
                        'analysis': data.get('analysis', {}),
                        'raw_data': data
                    }
                else:
                    return {'error': f'AlienVault OTX API error: {response.status}'}
        except Exception as e:
            logger.error(f"AlienVault OTX query failed: {e}")
            return {'error': str(e)}
    
    async def query_github_intelligence(self, username: str) -> Dict[str, Any]:
        """Query GitHub using user's API token"""
        try:
            api_token = os.getenv('GITHUB_API_TOKEN', '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')
            headers = {'Authorization': f'token {api_token}'}
            
            # Get user info
            user_url = f"https://api.github.com/users/{username}"
            async with self.session.get(user_url, headers=headers) as response:
                if response.status == 200:
                    user_data = await response.json()
                    
                    # Get repositories
                    repos_url = f"https://api.github.com/users/{username}/repos"
                    async with self.session.get(repos_url, headers=headers) as repos_response:
                        repos_data = await repos_response.json() if repos_response.status == 200 else []
                    
                    return {
                        'source': 'GitHub (User API)',
                        'username': username,
                        'profile': {
                            'name': user_data.get('name'),
                            'company': user_data.get('company'),
                            'location': user_data.get('location'),
                            'email': user_data.get('email'),
                            'bio': user_data.get('bio'),
                            'public_repos': user_data.get('public_repos', 0),
                            'followers': user_data.get('followers', 0),
                            'following': user_data.get('following', 0),
                            'created_at': user_data.get('created_at'),
                            'updated_at': user_data.get('updated_at')
                        },
                        'repositories': [
                            {
                                'name': repo.get('name'),
                                'description': repo.get('description'),
                                'language': repo.get('language'),
                                'stars': repo.get('stargazers_count', 0),
                                'forks': repo.get('forks_count', 0),
                                'updated_at': repo.get('updated_at')
                            }
                            for repo in repos_data[:10]  # Top 10 repos
                        ]
                    }
                else:
                    return {'error': f'GitHub API error: {response.status}'}
        except Exception as e:
            logger.error(f"GitHub query failed: {e}")
            return {'error': str(e)}
    
    async def query_etherscan_address(self, address: str) -> Dict[str, Any]:
        """Query Etherscan using user's API key"""
        try:
            api_key = os.getenv('ETHERSCAN_API_KEY', 'VXVJX5N1UM44KUYMJDAVZBKJ3I5ATWDB6E')
            
            # Get balance
            balance_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
            
            async with self.session.get(balance_url) as response:
                if response.status == 200:
                    balance_data = await response.json()
                    
                    # Get transaction list
                    tx_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10&sort=desc&apikey={api_key}"
                    
                    async with self.session.get(tx_url) as tx_response:
                        tx_data = await tx_response.json() if tx_response.status == 200 else {}
                    
                    balance_eth = int(balance_data.get('result', '0')) / 10**18 if balance_data.get('result') else 0
                    
                    return {
                        'source': 'Etherscan (User API)',
                        'address': address,
                        'balance_eth': balance_eth,
                        'balance_wei': balance_data.get('result', '0'),
                        'transaction_count': len(tx_data.get('result', [])),
                        'recent_transactions': [
                            {
                                'hash': tx.get('hash'),
                                'from': tx.get('from'),
                                'to': tx.get('to'),
                                'value_eth': int(tx.get('value', '0')) / 10**18 if tx.get('value') else 0,
                                'timestamp': tx.get('timeStamp')
                            }
                            for tx in tx_data.get('result', [])[:5]  # Top 5 transactions
                        ]
                    }
                else:
                    return {'error': f'Etherscan API error: {response.status}'}
        except Exception as e:
            logger.error(f"Etherscan query failed: {e}")
            return {'error': str(e)}
    
    async def query_multi_chain_address(self, address: str, networks: list = None) -> Dict[str, Any]:
        """Query address across multiple EVM chains using user's Etherscan API key"""
        try:
            api_key = os.getenv('ETHERSCAN_API_KEY', 'VXVJX5N1UM44KUYMJDAVZBKJ3I5ATWDB6E')
            
            # EVM-compatible chains using Etherscan V2 API (single endpoint, different chainids)
            chain_configs = {
                "ethereum": {"endpoint": "api.etherscan.io/v2", "chainid": 1, "symbol": "ETH", "decimals": 18, "name": "Ethereum", "color": "🔵"},
                "polygon": {"endpoint": "api.etherscan.io/v2", "chainid": 137, "symbol": "MATIC", "decimals": 18, "name": "Polygon", "color": "🟣"},
                "bsc": {"endpoint": "api.etherscan.io/v2", "chainid": 56, "symbol": "BNB", "decimals": 18, "name": "BSC", "color": "🟡"},
                "arbitrum": {"endpoint": "api.etherscan.io/v2", "chainid": 42161, "symbol": "ETH", "decimals": 18, "name": "Arbitrum", "color": "🔴"},
                "optimism": {"endpoint": "api.etherscan.io/v2", "chainid": 10, "symbol": "ETH", "decimals": 18, "name": "Optimism", "color": "🔴"},
                "base": {"endpoint": "api.etherscan.io/v2", "chainid": 8453, "symbol": "ETH", "decimals": 18, "name": "Base", "color": "🔷"},
                "avalanche": {"endpoint": "api.etherscan.io/v2", "chainid": 43114, "symbol": "AVAX", "decimals": 18, "name": "Avalanche", "color": "❄️"}
            }
            
            # Default to major chains if none specified
            if not networks:
                networks = ["ethereum", "polygon", "bsc", "arbitrum"]
            
            multi_chain_results = {
                'source': 'Multi-Chain EVM Analysis (User Etherscan API)',
                'address': address,
                'chains_analyzed': len(networks),
                'total_chains_with_activity': 0,
                'chain_data': {},
                'cross_chain_summary': {
                    'total_native_value': 0,
                    'active_chains': [],
                    'total_transactions': 0
                }
            }
            
            for network in networks:
                if network not in chain_configs:
                    continue
                    
                config = chain_configs[network]
                
                try:
                    # Get balance using V2 API with chainid
                    balance_url = f"https://{config['endpoint']}/api?chainid={config['chainid']}&module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
                    
                    async with self.session.get(balance_url) as response:
                        if response.status == 200:
                            balance_data = await response.json()
                            
                            # Get transaction count using V2 API
                            tx_url = f"https://{config['endpoint']}/api?chainid={config['chainid']}&module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=5&sort=desc&apikey={api_key}"
                            
                            async with self.session.get(tx_url) as tx_response:
                                tx_data = await tx_response.json() if tx_response.status == 200 else {}
                            
                            balance_wei = int(balance_data.get('result', '0'))
                            balance_native = balance_wei / (10**config['decimals']) if balance_wei else 0
                            tx_count = len(tx_data.get('result', []))
                            
                            # Track active chains
                            if balance_native > 0 or tx_count > 0:
                                multi_chain_results['total_chains_with_activity'] += 1
                                multi_chain_results['cross_chain_summary']['active_chains'].append(f"{config['color']} {config['name']}")
                                multi_chain_results['cross_chain_summary']['total_transactions'] += tx_count
                            
                            multi_chain_results['chain_data'][network] = {
                                'network_name': config['name'],
                                'symbol': config['symbol'],
                                'color': config['color'],
                                'balance': balance_native,
                                'balance_wei': str(balance_wei),
                                'transaction_count': tx_count,
                                'has_activity': balance_native > 0 or tx_count > 0,
                                'recent_transactions': [
                                    {
                                        'hash': tx.get('hash'),
                                        'from': tx.get('from'),
                                        'to': tx.get('to'),
                                        'value': int(tx.get('value', '0')) / (10**config['decimals']),
                                        'timestamp': tx.get('timeStamp')
                                    } for tx in tx_data.get('result', [])[:3]
                                ],
                                'endpoint': config['endpoint']
                            }
                            
                        else:
                            multi_chain_results['chain_data'][network] = {
                                'network_name': config['name'],
                                'error': f'{config["name"]} API error: {response.status}'
                            }
                            
                except Exception as e:
                    multi_chain_results['chain_data'][network] = {
                        'network_name': config['name'],
                        'error': f'{config["name"]} query failed: {str(e)}'
                    }
            
            return multi_chain_results
                    
        except Exception as e:
            logger.error(f"Multi-chain query failed: {e}")
            return {'error': f'Multi-chain EVM analysis failed: {str(e)}'}
    
    async def query_newsapi(self, query: str) -> Dict[str, Any]:
        """Query NewsAPI using user's API key"""
        try:
            api_key = os.getenv('NEWSAPI_KEY', '43f407a4aceb41c4a588224bfbf7f528')
            url = f"https://newsapi.org/v2/everything?q={quote(query)}&sortBy=publishedAt&pageSize=10&apiKey={api_key}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'NewsAPI (User API)',
                        'query': query,
                        'total_results': data.get('totalResults', 0),
                        'articles': [
                            {
                                'title': article.get('title'),
                                'description': article.get('description'),
                                'url': article.get('url'),
                                'source': article.get('source', {}).get('name'),
                                'published_at': article.get('publishedAt'),
                                'author': article.get('author')
                            }
                            for article in data.get('articles', [])
                        ]
                    }
                else:
                    return {'error': f'NewsAPI error: {response.status}'}
        except Exception as e:
            logger.error(f"NewsAPI query failed: {e}")
            return {'error': str(e)}
    
    async def query_hunter_io(self, domain: str) -> Dict[str, Any]:
        """Query Hunter.io using user's API key"""
        try:
            api_key = os.getenv('HUNTER_IO_API_KEY', '98df4bbbac21d3f2dfae2e657e09520b82b94bb0')
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    domain_data = data.get('data', {})
                    return {
                        'source': 'Hunter.io (User API)',
                        'domain': domain,
                        'organization': domain_data.get('organization'),
                        'emails_found': len(domain_data.get('emails', [])),
                        'confidence': domain_data.get('confidence'),
                        'emails': [
                            {
                                'value': email.get('value'),
                                'type': email.get('type'),
                                'confidence': email.get('confidence'),
                                'first_name': email.get('first_name'),
                                'last_name': email.get('last_name'),
                                'position': email.get('position')
                            }
                            for email in domain_data.get('emails', [])[:10]  # Top 10 emails
                        ]
                    }
                else:
                    return {'error': f'Hunter.io API error: {response.status}'}
        except Exception as e:
            logger.error(f"Hunter.io query failed: {e}")
            return {'error': str(e)}
    
    async def query_threatcrowd(self, indicator: str, indicator_type: str = 'domain') -> Dict[str, Any]:
        """Query ThreatCrowd for real threat intelligence"""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/{indicator_type}/report/"
            params = {indicator_type: indicator}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'ThreatCrowd',
                        'indicator': indicator,
                        'response_code': data.get('response_code', 0),
                        'resolutions': data.get('resolutions', []),
                        'hashes': data.get('hashes', []),
                        'emails': data.get('emails', []),
                        'subdomains': data.get('subdomains', []),
                        'raw_data': data
                    }
                else:
                    return {'error': f'ThreatCrowd API error: {response.status}'}
        except Exception as e:
            logger.error(f"ThreatCrowd query failed: {e}")
            return {'error': str(e)}
    
    async def query_crtsh(self, domain: str) -> Dict[str, Any]:
        """Query crt.sh for real SSL certificate data"""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Process certificate data
                    certificates = []
                    unique_names = set()
                    
                    for cert in data[:50]:  # Limit to first 50 results
                        name_value = cert.get('name_value', '')
                        if name_value:
                            for name in name_value.split('\n'):
                                name = name.strip()
                                if name and name not in unique_names:
                                    unique_names.add(name)
                                    certificates.append({
                                        'id': cert.get('id'),
                                        'name': name,
                                        'issuer': cert.get('issuer_name'),
                                        'not_before': cert.get('not_before'),
                                        'not_after': cert.get('not_after')
                                    })
                    
                    return {
                        'source': 'crt.sh',
                        'domain': domain,
                        'certificates_found': len(certificates),
                        'unique_subdomains': len(unique_names),
                        'certificates': certificates[:20],  # Return top 20
                        'subdomains': sorted(list(unique_names))[:50]  # Return top 50
                    }
                else:
                    return {'error': f'crt.sh API error: {response.status}'}
        except Exception as e:
            logger.error(f"crt.sh query failed: {e}")
            return {'error': str(e)}
    
    async def query_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Query free IP geolocation services"""
        results = {}
        
        # Try multiple free services
        services = [
            ('ip-api.com', f'http://ip-api.com/json/{ip}'),
            ('ipapi.co', f'https://ipapi.co/{ip}/json/'),
            ('freegeoip.app', f'https://freegeoip.app/json/{ip}')
        ]
        
        for service_name, url in services:
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        results[service_name] = data
                        break  # Use first successful response
            except Exception as e:
                logger.warning(f"{service_name} geolocation failed: {e}")
                continue
        
        if results:
            # Normalize the response from whichever service worked
            service_data = list(results.values())[0]
            return {
                'source': 'IP Geolocation Services',
                'ip': ip,
                'country': service_data.get('country') or service_data.get('country_name'),
                'region': service_data.get('region') or service_data.get('regionName'),
                'city': service_data.get('city'),
                'latitude': service_data.get('lat') or service_data.get('latitude'),
                'longitude': service_data.get('lon') or service_data.get('longitude'),
                'isp': service_data.get('isp') or service_data.get('org'),
                'timezone': service_data.get('timezone'),
                'raw_data': service_data
            }
        else:
            return {'error': 'All IP geolocation services failed'}
    
    async def query_security_feeds(self) -> Dict[str, Any]:
        """Query real security RSS feeds"""
        feeds_data = {}
        
        feeds = [
            ('CISA Alerts', 'https://www.cisa.gov/uscert/ncas/alerts.xml'),
            ('SANS ISC', 'https://isc.sans.edu/rssfeed.xml'),
            ('Krebs on Security', 'https://krebsonsecurity.com/feed/')
        ]
        
        for feed_name, feed_url in feeds:
            try:
                async with self.session.get(feed_url) as response:
                    if response.status == 200:
                        feed_content = await response.text()
                        # Parse RSS feed
                        feed = feedparser.parse(feed_content)
                        
                        entries = []
                        for entry in feed.entries[:10]:  # Get latest 10 entries
                            entries.append({
                                'title': entry.get('title', ''),
                                'link': entry.get('link', ''),
                                'published': entry.get('published', ''),
                                'summary': entry.get('summary', '')[:200] + '...' if len(entry.get('summary', '')) > 200 else entry.get('summary', '')
                            })
                        
                        feeds_data[feed_name] = {
                            'title': feed.feed.get('title', feed_name),
                            'description': feed.feed.get('description', ''),
                            'entries': entries
                        }
            except Exception as e:
                logger.warning(f"RSS feed {feed_name} failed: {e}")
                continue
        
        return {
            'source': 'Security RSS Feeds',
            'feeds_count': len(feeds_data),
            'feeds': feeds_data,
            'timestamp': time.time()
        }
    
    async def query_wayback_machine(self, url: str) -> Dict[str, Any]:
        """Query Wayback Machine for archived snapshots"""
        try:
            api_url = f"https://web.archive.org/wayback/available?url={quote(url)}"
            
            async with self.session.get(api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if 'archived_snapshots' in data and 'closest' in data['archived_snapshots']:
                        snapshot = data['archived_snapshots']['closest']
                        return {
                            'source': 'Wayback Machine',
                            'url': url,
                            'available': snapshot.get('available', False),
                            'archived_url': snapshot.get('url', ''),
                            'timestamp': snapshot.get('timestamp', ''),
                            'status': snapshot.get('status', ''),
                            'raw_data': data
                        }
                    else:
                        return {
                            'source': 'Wayback Machine',
                            'url': url,
                            'available': False,
                            'message': 'No archived snapshots found'
                        }
                else:
                    return {'error': f'Wayback Machine API error: {response.status}'}
        except Exception as e:
            logger.error(f"Wayback Machine query failed: {e}")
            return {'error': str(e)}
    
    def get_real_source_statistics(self) -> Dict[str, Any]:
        """Get statistics about real, accessible OSINT sources"""
        configured = self.get_configured_sources()
        
        category_counts = {}
        for category in SourceCategory:
            category_sources = self.get_sources_by_category(category)
            category_counts[category.value] = {
                'total': len(category_sources),
                'configured': len([s for s in category_sources.values() 
                                if not s.requires_auth or (s.api_key_env and os.getenv(s.api_key_env))]),
                'free': len([s for s in category_sources.values() if s.free_tier])
            }
        
        return {
            'total_sources': len(self.sources),
            'configured_sources': len(configured),
            'free_sources': len([s for s in self.sources.values() if s.free_tier]),
            'categories': category_counts,
            'reliability_distribution': {
                'premium': len([s for s in self.sources.values() if s.reliability_score >= 0.9]),
                'high': len([s for s in self.sources.values() if 0.8 <= s.reliability_score < 0.9]),
                'medium': len([s for s in self.sources.values() if 0.7 <= s.reliability_score < 0.8]),
                'basic': len([s for s in self.sources.values() if s.reliability_score < 0.7])
            },
            'authentication_required': len([s for s in self.sources.values() if s.requires_auth]),
            'completely_free': len([s for s in self.sources.values() if not s.requires_auth and s.free_tier])
        }
    
    def get_configured_sources(self) -> Dict[str, RealOSINTSource]:
        """Get all configured sources with valid API keys or no auth required"""
        configured = {}
        for name, source in self.sources.items():
            if not source.requires_auth or (source.api_key_env and os.getenv(source.api_key_env)):
                configured[name] = source
        return configured
    
    def get_sources_by_category(self, category: SourceCategory) -> Dict[str, RealOSINTSource]:
        """Get sources filtered by category"""
        return {name: source for name, source in self.sources.items() 
                if source.category == category}

# Global instance
realistic_osint_manager = RealisticOSINTManager()

# Convenience functions
async def get_real_source_statistics():
    """Get statistics about real OSINT sources"""
    async with realistic_osint_manager as manager:
        return manager.get_real_source_statistics()

async def query_real_threat_intelligence(indicator: str, indicator_type: str = 'domain'):
    """Query real threat intelligence sources including user's APIs"""
    async with realistic_osint_manager as manager:
        results = {}
        
        # Query user's premium sources first
        results['alienvault_otx'] = await manager.query_alienvault_otx(indicator, indicator_type)
        
        # Query free sources
        results['threatcrowd'] = await manager.query_threatcrowd(indicator, indicator_type)
        
        # Query additional free sources based on availability
        # Add more real queries here as needed
        
        return {
            'indicator': indicator,
            'type': indicator_type,
            'sources_queried': len(results),
            'results': results,
            'premium_sources_used': ['AlienVault OTX (User API)'],
            'timestamp': time.time()
        }

async def query_real_domain_intelligence(domain: str):
    """Query real domain intelligence sources including user's APIs"""
    async with realistic_osint_manager as manager:
        results = {}
        
        # Query user's premium sources
        results['hunter_io'] = await manager.query_hunter_io(domain)
        
        # Query free sources
        results['certificates'] = await manager.query_crtsh(domain)
        results['security_feeds'] = await manager.query_security_feeds()
        results['wayback'] = await manager.query_wayback_machine(f"https://{domain}")
        
        return {
            'domain': domain,
            'sources_queried': len(results),
            'results': results,
            'premium_sources_used': ['Hunter.io (User API)'],
            'timestamp': time.time()
        }

async def query_real_ip_intelligence(ip: str):
    """Query real IP intelligence sources"""
    async with realistic_osint_manager as manager:
        results = {}
        
        # Query geolocation services
        results['geolocation'] = await manager.query_ip_geolocation(ip)
        
        # Query ThreatCrowd for IP intelligence
        results['threatcrowd'] = await manager.query_threatcrowd(ip, 'ip')
        
        return {
            'ip': ip,
            'sources_queried': len(results),
            'results': results,
            'timestamp': time.time()
        }

# ============================================================================
# CLI INTERFACE FOR STANDALONE USAGE
# ============================================================================

if __name__ == "__main__":
    import sys
    import argparse
    
    async def main():
        parser = argparse.ArgumentParser(description='Apollo Sentinel Realistic OSINT Sources')
        parser.add_argument('command', choices=['stats', 'threat', 'domain', 'ip'], help='Command to execute')
        parser.add_argument('--indicator', help='Indicator to query (domain, IP, etc.)')
        parser.add_argument('--type', default='domain', help='Indicator type (domain, ip, hash, etc.)')
        
        args = parser.parse_args()
        
        if args.command == 'stats':
            stats = await get_real_source_statistics()
            print(json.dumps(stats, indent=2))
        
        elif args.command == 'threat':
            if not args.indicator:
                print("Error: --indicator required for threat command")
                return
            
            results = await query_real_threat_intelligence(args.indicator, args.type)
            print(json.dumps(results, indent=2))
        
        elif args.command == 'domain':
            if not args.indicator:
                print("Error: --indicator required for domain command")
                return
            
            results = await query_real_domain_intelligence(args.indicator)
            print(json.dumps(results, indent=2))
        
        elif args.command == 'ip':
            if not args.indicator:
                print("Error: --indicator required for ip command")
                return
            
            results = await query_real_ip_intelligence(args.indicator)
            print(json.dumps(results, indent=2))
    
    # Run the async main function
    asyncio.run(main())
