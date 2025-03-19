from bs4 import BeautifulSoup
from bs4.element import Comment
import requests
import csv
import sys
import json
import re
import os
import logging
import threading
import queue
from datetime import datetime, timedelta
import asyncio
import aiohttp
import streamlit as st
import pandas as pd
import base64
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("tech_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Simple sentence tokenizer that doesn't require NLTK
def simple_sent_tokenize(text):
    """Simple sentence tokenization fallback."""
    sentences = []
    for s in re.split(r'(?<=[.!?])\s+', text):
        if s:
            sentences.append(s)
    return sentences

# Configuration
OUTPUT_FILE = "tech_updates.json"
DEFAULT_DAYS_AGO = 2  # Default to fetch articles from today and yesterday
DEFAULT_RESULTS_COUNT = 10  # Default number of results to show
MAX_CONCURRENT_REQUESTS = 10  # Limit concurrent requests to prevent overloading

# API KEYS - Set your OpenAI API key here
# API KEYS - Replace with your actual API keys
OPENAI_API_KEY = st.secrets.get("OPENAI_API_KEY", "")

# List of top vendors/products to track
TOP_VENDORS = [
    "Microsoft", "Azure", "Windows", "Office 365", 
    "AWS", "Amazon Web Services", "EC2", "S3",
    "Google", "GCP", "Google Cloud", "Chrome",
    "Cisco", "IOS", "Webex", "Talos",
    "Oracle", "Java", "PeopleSoft", "WebLogic",
    "VMware", "ESXi", "vSphere", "NSX",
    "Fortinet", "FortiGate", "FortiOS",
    "Palo Alto", "PAN-OS", "Prisma",
    "Citrix", "XenApp", "NetScaler",
    "IBM", "WebSphere", "Db2",
    "SAP", "HANA", "NetWeaver",
    "Salesforce", "ServiceNow",
    "Adobe", "Acrobat", "Reader", "Creative Cloud",
    "Linux", "Ubuntu", "Red Hat", "RHEL", "CentOS",
    "Android", "iOS", "macOS",
    "Juniper", "Junos",
    "Docker", "Kubernetes", "K8s",
    "Splunk", "CrowdStrike", "Symantec", "McAfee", "Trend Micro",
    "F5", "BIG-IP", "Checkpoint", "SonicWall"
]

# Keywords to identify different types of updates
INCIDENT_KEYWORDS = [
    "vulnerability", "exploit", "attack", "breach", "compromise", 
    "malware", "ransomware", "phishing", "data leak", "zero-day",
    "CVE", "patch", "security flaw", "backdoor", "threat", "risk",
    "critical", "high severity", "remote code execution", "RCE",
    "privilege escalation", "denial of service", "DoS", "data exposure",
    "security update", "security advisory", "security bulletin", "security hotfix"
]

PRODUCT_RELEASE_KEYWORDS = [
    "release", "version", "upgrade", "update", "new feature", "GA ", 
    "general availability", "product launch", "now available", "released",
    "announcement", "introduces", "unveils", "launches", "debuts",
    "RTM ", "production ready", "stable release", "major update"
]

# RSS Feeds - Enhanced with more product announcement sources
RSS_FEEDS = [
    # Security focused sources
    "https://www.sans.org/newsletters/at-risk/",
    "https://isc.sans.edu/diaryarchive.html",
    "https://us-cert.cisa.gov/ncas",
    "https://isc.sans.edu/podcast.html",
    "https://aws.amazon.com/security/security-bulletins/",
    "https://www.bleepingcomputer.com/",
    "https://securelist.com/",
    "https://www.trendmicro.com/en_us/research.html",
    "https://blog.malwarebytes.com/",
    "https://cofense.com/blog/",
    "https://thehackernews.com/",
    "https://krebsonsecurity.com/",
    "https://blog.talosintelligence.com/",
    "https://www.crowdstrike.com/blog/",
    "https://research.checkpoint.com/latest-publications/",
    "https://nakedsecurity.sophos.com/",
    "https://unit42.paloaltonetworks.com/",
    "https://www.mandiant.com/resources/blog/",
    "https://www.sentinelone.com/blog/",
    
    # Product announcement/update sources
    "https://azure.microsoft.com/en-us/updates/",
    "https://aws.amazon.com/new/",
    "https://cloud.google.com/blog/products/",
    "https://devblogs.microsoft.com/",
    "https://www.cisco.com/c/en/us/products/cloud-systems-management/whats-new.html",
    "https://www.vmware.com/company/news.html",
    "https://www.redhat.com/en/blog",
    "https://www.paloaltonetworks.com/blog",
    "https://www.fortinet.com/blog/business-and-technology",
    "https://www.ibm.com/blogs/",
    "https://www.oracle.com/news/"
]

# Convert regular website URLs to RSS feed URLs where possible
RSS_FEED_MAPPINGS = {
    "https://www.sans.org/newsletters/at-risk/": "https://www.sans.org/newsletters/at-risk/rss/",
    "https://isc.sans.edu/diaryarchive.html": "https://isc.sans.edu/rssfeed.xml",
    "https://us-cert.cisa.gov/ncas": "https://us-cert.cisa.gov/ncas/all.xml",
    "https://isc.sans.edu/podcast.html": "https://isc.sans.edu/podcast.xml",
    "https://aws.amazon.com/security/security-bulletins/": "https://aws.amazon.com/blogs/security/feed/",
    "https://www.bleepingcomputer.com/": "https://www.bleepingcomputer.com/feed/",
    "https://securelist.com/": "https://securelist.com/feed/",
    "https://www.trendmicro.com/en_us/research.html": "https://feeds.feedburner.com/TrendMicroSimplySecurity",
    "https://blog.malwarebytes.com/": "https://www.malwarebytes.com/blog/feed/index.xml",
    "https://cofense.com/blog/": "https://cofense.com/blog/feed/",
    "https://thehackernews.com/": "https://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/": "https://krebsonsecurity.com/feed/",
    "https://blog.talosintelligence.com/": "https://blog.talosintelligence.com/rss/",
    "https://www.crowdstrike.com/blog/": "https://www.crowdstrike.com/blog/feed/",
    "https://research.checkpoint.com/latest-publications/": "https://research.checkpoint.com/feed/",
    "https://nakedsecurity.sophos.com/": "https://nakedsecurity.sophos.com/feed/",
    "https://unit42.paloaltonetworks.com/": "https://unit42.paloaltonetworks.com/feed/",
    "https://www.mandiant.com/resources/blog/": "https://www.mandiant.com/resources/blog/rss.xml",
    "https://www.sentinelone.com/blog/": "https://www.sentinelone.com/blog/feed/",
    
    # Product announcement feeds
    "https://azure.microsoft.com/en-us/updates/": "https://azurecomcdn.azureedge.net/en-us/updates/feed/",
    "https://aws.amazon.com/new/": "https://aws.amazon.com/about-aws/whats-new/recent/feed/",
    "https://cloud.google.com/blog/products/": "https://cloudblog.withgoogle.com/products/rss/",
    "https://devblogs.microsoft.com/": "https://devblogs.microsoft.com/feed/",
    "https://www.redhat.com/en/blog": "https://www.redhat.com/en/rss/blog",
    "https://www.paloaltonetworks.com/blog": "https://www.paloaltonetworks.com/blog/feed",
    "https://www.fortinet.com/blog/business-and-technology": "https://www.fortinet.com/blog/business-and-technology/rss.xml",
    "https://www.ibm.com/blogs/": "https://www.ibm.com/blogs/feed/atom/",
    "https://www.oracle.com/news/": "https://www.oracle.com/news/rss.html"
}

# Blocklist for filtering out low-quality content
CONTENT_BLOCKLIST = [
    "weekly roundup",
    "week in security",
    "security roundup",
    "security recap",
    "newsletter",
    "subscribe",
    "weekly digest",
    "week in review",
    "roundup of news",
    "webinar recording"
]

def tag_visible(element):
    """Filter out invisible elements from HTML."""
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    try:
        if True in [value in ["related-articles", "sidebar", "comment", "footer"] for value in element.parent.attrs.values()]:
            return False
    except KeyError:
        pass
    return True

def is_recent_date(date_str, days_ago):
    """
    Check if a date string represents a date within the specified timeframe.
    """
    try:
        # Current date at midnight
        now = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = now - timedelta(days=days_ago)
        
        # Try standard RSS date format first
        standard_formats = [
            "%a, %d %b %Y %H:%M:%S %z",  # Wed, 18 Mar 2025 10:30:00 +0000
            "%a, %d %b %Y %H:%M:%S %Z",  # Wed, 18 Mar 2025 10:30:00 GMT
            "%Y-%m-%d %H:%M:%S",         # 2025-03-18 10:30:00
            "%Y-%m-%d",                  # 2025-03-18
            "%d %b %Y %H:%M:%S",         # 18 Mar 2025 10:30:00
            "%d %b %Y",                  # 18 Mar 2025
            "%b %d, %Y",                 # Mar 18, 2025
        ]
        
        # Try each format
        for fmt in standard_formats:
            try:
                date_obj = datetime.strptime(date_str, fmt)
                return date_obj >= cutoff_date
            except ValueError:
                continue
        
        # Extract year, month, day from the string
        year_match = re.search(r'(?:19|20)\d{2}', date_str)  # Match years 1900-2099
        
        if not year_match:
            logger.warning(f"No year found in date string: {date_str}")
            return False
        
        year = year_match.group(0)
        
        # Find month
        month_patterns = {
            'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06',
            'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
        }
        
        month = None
        for month_name, month_num in month_patterns.items():
            if month_name in date_str:
                month = month_num
                break
        
        if not month:
            logger.warning(f"No month found in date string: {date_str}")
            return False
        
        # Find day
        day_match = re.search(r'\b(\d{1,2})\b', date_str)
        if not day_match:
            logger.warning(f"No day found in date string: {date_str}")
            return False
        
        day = day_match.group(0).zfill(2)  # Pad single digits with leading zero
        
        # Construct date and compare
        try:
            constructed_date = datetime.strptime(f"{year}-{month}-{day}", "%Y-%m-%d")
            return constructed_date >= cutoff_date
        except ValueError:
            logger.warning(f"Failed to construct date from {year}-{month}-{day}")
            return False
    
    except Exception as e:
        logger.error(f"Error checking date recency: {e} for date: {date_str}")
        return False

def extract_text_from_html(html_content):
    """Extract readable text from HTML content."""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        texts = soup.findAll(string=True)  # Use string= instead of text= to avoid deprecation warning
        visible_texts = filter(tag_visible, texts)
        return ' '.join(t.strip() for t in visible_texts if t.strip())
    except Exception as e:
        logger.error(f"Error extracting text from HTML: {e}")
        return ""

def identify_vendors(text):
    """Identify mentioned vendors in the text."""
    found_vendors = []
    for vendor in TOP_VENDORS:
        pattern = r'\b' + re.escape(vendor) + r'\b'
        if re.search(pattern, text, re.IGNORECASE):
            found_vendors.append(vendor)
    return list(set(found_vendors))

def is_blocked_content(title, description=""):
    """Check if the content is in the blocklist (low quality)."""
    combined_text = (title + " " + description).lower()
    for term in CONTENT_BLOCKLIST:
        if term.lower() in combined_text:
            return True
    return False

def identify_update_type(text):
    """
    Identify the type of update: security incident or product release.
    Returns a tuple of (type, relevant_keywords)
    """
    text_lower = text.lower()
    
    # Check for security incidents
    security_keywords = []
    for keyword in INCIDENT_KEYWORDS:
        if keyword.lower() in text_lower:
            security_keywords.append(keyword)
    
    # Check for product releases
    product_keywords = []
    for keyword in PRODUCT_RELEASE_KEYWORDS:
        if keyword.lower() in text_lower:
            product_keywords.append(keyword)
    
    # Determine the primary type
    if security_keywords and len(security_keywords) > len(product_keywords):
        return ("security_incident", security_keywords)
    elif product_keywords:
        return ("product_release", product_keywords)
    elif security_keywords:  # Fallback if both have same count
        return ("security_incident", security_keywords)
    else:
        return ("other", [])

def extract_summary(text, vendors, keywords, max_sentences=3):
    """Extract sentences relevant to the update."""
    # Use our simple sentence tokenizer
    sentences = simple_sent_tokenize(text)
    relevant_sentences = []
    
    for sentence in sentences:
        sentence_lower = sentence.lower()
        if any(vendor.lower() in sentence_lower for vendor in vendors):
            if any(keyword.lower() in sentence_lower for keyword in keywords):
                relevant_sentences.append(sentence)
    
    # If we don't have enough vendor-specific sentences, get sentences with keywords
    if len(relevant_sentences) < max_sentences:
        for sentence in sentences:
            if sentence not in relevant_sentences:
                if any(keyword.lower() in sentence.lower() for keyword in keywords):
                    relevant_sentences.append(sentence)
                    if len(relevant_sentences) >= max_sentences:
                        break
    
    # Limit to max sentences
    summary = " ".join(relevant_sentences[:max_sentences])
    
    # If still no summary, take the first few sentences as a fallback
    if not summary and sentences:
        summary = " ".join(sentences[:max_sentences])
    
    return summary if summary else "Details not specified."

def calculate_relevance_score(title, summary, update_type, vendors):
    """Calculate a relevance score based on various factors."""
    score = 1  # Base score
    
    # Add points for relevant vendors
    score += min(len(vendors), 5)  # Up to 5 points for vendor relevance
    
    # Add points for well-known vendors
    major_vendors = ["Microsoft", "AWS", "Google", "Oracle", "IBM", "Cisco", "SAP", "VMware"]
    for vendor in vendors:
        if vendor in major_vendors:
            score += 2
    
    # Add points based on update type
    if update_type[0] == "security_incident":
        severity_terms = {
            "critical": 5,
            "high": 4,
            "remote code execution": 5,
            "privilege escalation": 4,
            "zero-day": 5,
            "ransomware": 5,
            "data breach": 4,
            "backdoor": 4,
            "exploit": 3,
            "vulnerability": 3,
            "cve": 3,
            "patch": 2,
            "update": 1
        }
        
        combined_text = (title + " " + summary).lower()
        
        for term, value in severity_terms.items():
            if term in combined_text:
                score += value
    
    elif update_type[0] == "product_release":
        release_terms = {
            "major release": 4,
            "new version": 3,
            "general availability": 4,
            "ga release": 4,
            "new product": 5,
            "new feature": 3,
            "version": 2,
            "upgrade": 2,
            "update": 1
        }
        
        combined_text = (title + " " + summary).lower()
        
        for term, value in release_terms.items():
            if term in combined_text:
                score += value
    
    # Title length factor (avoid very short titles which might be low quality)
    if len(title) > 60:
        score += 2
    elif len(title) < 20:
        score -= 2
    
    # Summary content factor (avoid very short summaries)
    if len(summary) > 200:
        score += 2
    elif len(summary) < 50:
        score -= 1
    
    return score

def create_update_summary(title, link, vendors, summary, pub_date, source, update_type):
    """Create a structured summary of the update."""
    return {
        "title": title,
        "link": link,
        "vendors": vendors,
        "summary": summary,
        "update_type": update_type[0],
        "keywords": update_type[1],
        "publication_date": pub_date,
        "source": source,
        "relevance_score": calculate_relevance_score(title, summary, update_type, vendors)
    }

class AsyncRssFetcher:
    """Asynchronous class for fetching RSS feeds."""
    
    def __init__(self, days_ago):
        self.days_ago = days_ago
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0'
        }
        self.updates = []
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    
    async def fetch_feed(self, url):
        """Fetch a single RSS feed."""
        source_name = url.split('/')[2]
        try:
            # Convert to RSS feed URL if available
            feed_url = RSS_FEED_MAPPINGS.get(url, url)
            
            async with self.semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(feed_url, headers=self.headers) as response:
                        if response.status != 200:
                            logger.warning(f"Failed to fetch {feed_url}: HTTP {response.status}")
                            return []
                        
                        content = await response.text()
                        
                        soup = BeautifulSoup(content, 'html.parser')
                        items = soup.findAll('item')
                        
                        feed_updates = []
                        
                        for item in items:
                            try:
                                # Extract item details
                                title_tag = item.find('title')
                                title = title_tag.text if title_tag else ""
                                
                                if not title or is_blocked_content(title):
                                    continue
                                
                                link_tag = item.find('link')
                                link = ""
                                if link_tag:
                                    if link_tag.string:
                                        link = link_tag.string
                                    elif link_tag.text:
                                        link = link_tag.text
                                    elif link_tag.next_sibling and isinstance(link_tag.next_sibling, str):
                                        link = link_tag.next_sibling.strip()
                                
                                desc_tag = item.find('description')
                                description = desc_tag.text if desc_tag else ""
                                
                                date_tag = item.find('pubdate') or item.find('pubDate')
                                pub_date = date_tag.text if date_tag else ""
                                
                                # Check if item is recent
                                if not pub_date or not is_recent_date(pub_date, self.days_ago):
                                    continue
                                
                                # Check for vendor mentions in title/description
                                vendors = identify_vendors(title + " " + description)
                                if not vendors:
                                    continue
                                
                                # Determine update type
                                update_type = identify_update_type(title + " " + description)
                                if update_type[0] == "other":
                                    continue
                                
                                # Create preliminary update
                                update = {
                                    "title": title,
                                    "link": link.strip(),
                                    "description": description,
                                    "pub_date": pub_date,
                                    "source": source_name,
                                    "vendors": vendors,
                                    "update_type": update_type
                                }
                                
                                feed_updates.append(update)
                                
                            except Exception as e:
                                logger.error(f"Error processing RSS item: {e}")
                                continue
                        
                        return feed_updates
                        
        except Exception as e:
            logger.error(f"Error fetching feed {url}: {e}")
            return []
    
    async def process_article(self, update):
        """Fetch and process a single article."""
        try:
            async with self.semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(update["link"], headers=self.headers) as response:
                        if response.status != 200:
                            logger.warning(f"Failed to fetch article {update['link']}: HTTP {response.status}")
                            return None
                        
                        content = await response.text()
                        article_text = extract_text_from_html(content)
                        
                        # Extract a relevant summary
                        summary = extract_summary(
                            article_text, 
                            update["vendors"], 
                            update["update_type"][1]
                        )
                        
                        # Create the final update summary
                        final_update = create_update_summary(
                            title=update["title"],
                            link=update["link"],
                            vendors=update["vendors"],
                            summary=summary,
                            pub_date=update["pub_date"],
                            source=update["source"],
                            update_type=update["update_type"]
                        )
                        
                        return final_update
                        
        except Exception as e:
            logger.error(f"Error processing article {update['link']}: {e}")
            return None
    
    async def fetch_all(self):
        """Fetch all RSS feeds and process articles."""
        # First, fetch all feeds
        feed_tasks = [self.fetch_feed(url) for url in RSS_FEEDS]
        feed_results = await asyncio.gather(*feed_tasks)
        
        # Flatten the list of updates
        preliminary_updates = []
        for result in feed_results:
            preliminary_updates.extend(result)
        
        # Process each article to get the full content
        article_tasks = [self.process_article(update) for update in preliminary_updates]
        article_results = await asyncio.gather(*article_tasks)
        
        # Filter out None results
        final_updates = [update for update in article_results if update]
        
        return final_updates

def get_tech_updates_openai(api_key, top_vendors, days):
    """
    Fetch technology updates using OpenAI API.
    
    Args:
        api_key (str): OpenAI API key
        top_vendors (list): List of vendors to track
        days (int): Number of days to look back
        
    Returns:
        list: List of update dictionaries
    """
    # Skip if no API key provided
    if not api_key or api_key == "your-openai-api-key-here":
        logger.warning("No valid OpenAI API key provided")
        return []
        
    # Format the vendors list for the prompt
    vendors_text = ", ".join(top_vendors[:20])  # Limit to 20 vendors to keep prompt size reasonable
    
    # Create the system prompt with emphasis on recency and variety
    system_prompt = f"""You are a technology analyst tasked with identifying important updates from the past {days} days. 
    Focus on updates involving these vendors: {vendors_text}.
    
    Include TWO types of updates:
    1. Security incidents: vulnerabilities, exploits, attacks, breaches, malware, patches
    2. Product releases: new versions, feature launches, general availability announcements
    
    IMPORTANT: Only include updates that have been published in the last {days} days. Do not include older updates.
    """
    
    # Create the user prompt
    user_prompt = f"""Search for technology updates from sources like:
    - sans.org, cisa.gov, bleepingcomputer.com (for security)
    - Microsoft.com, aws.amazon.com, cloud.google.com (for product releases)
    - vendor blogs and announcement pages
    
    For each update, provide:
    1. A clear title describing the update
    2. A list of affected vendors
    3. The update type: "security_incident" or "product_release"
    4. A 2-3 line summary of the key points
    5. The source URL
    6. The exact publication date in format "YYYY-MM-DD"
    
    Return 10 updates total with a mix of security incidents and product releases, prioritizing importance and recency.
    Format as a JSON object with an "updates" field containing an array of updates, each with fields: title, vendors, update_type, summary, source, and date.
    
    IMPORTANT: Ensure all updates are professional and newsworthy. Avoid weekly roundups, newsletters, or blog-style entries like "A week in security".
    """
    
    # Call OpenAI API
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "gpt-4o-mini",  # Use an available model
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2  # Lower temperature for more deterministic results
    }
    
    try:
        logger.info("Making request to OpenAI API")
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=60  # 60 second timeout
        )
        
        response.raise_for_status()  # Raise an exception for HTTP errors
        result = response.json()
        
        # Parse the JSON content from the response
        content = result['choices'][0]['message']['content']
        updates_data = json.loads(content)
        
        # Format the response to match your desired output format
        formatted_updates = []
        
        # Check if the updates data contains an 'updates' field
        updates = updates_data.get('updates', [])
        if not updates and isinstance(updates_data, list):
            # Handle case where API returns a direct array
            updates = updates_data
            
        logger.info(f"Received {len(updates)} updates from OpenAI API")
        
        for update in updates:
            # Extract vendors as a list if it's a string
            vendors = update.get("vendors", [])
            if isinstance(vendors, str):
                vendors = [v.strip() for v in vendors.split(',')]
                
            # Use the date provided by the API, or today's date if not available
            pub_date = update.get("date", datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0000"))
            
            # Determine the update type
            update_type = update.get("update_type", "other")
            if isinstance(update_type, str):
                # Convert string type to tuple format expected by the rest of the code
                if update_type == "security_incident":
                    keywords = [k for k in INCIDENT_KEYWORDS if k.lower() in update.get("summary", "").lower()]
                    update_type = ("security_incident", keywords if keywords else ["security"])
                elif update_type == "product_release":
                    keywords = [k for k in PRODUCT_RELEASE_KEYWORDS if k.lower() in update.get("summary", "").lower()]
                    update_type = ("product_release", keywords if keywords else ["release"])
                else:
                    update_type = ("other", [])
            
            formatted_updates.append({
                "title": update.get("title", ""),
                "vendors": vendors,
                "summary": update.get("summary", ""),
                "update_type": update_type[0],
                "keywords": update_type[1],
                "publication_date": pub_date,
                "source": update.get("source", "").split('/')[2] if '/' in update.get("source", "") else update.get("source", ""),
                "link": update.get("source", ""),
                "relevance_score": calculate_relevance_score(
                    update.get("title", ""), 
                    update.get("summary", ""), 
                    update_type, 
                    vendors
                )
            })
        
        return formatted_updates
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making request to OpenAI API: {e}")
        return []
    except (KeyError, json.JSONDecodeError) as e:
        logger.error(f"Error parsing response from OpenAI API: {e}")
        return []
