import pandas as pd
import requests
import datetime
import time
import json
import random
import re
import hashlib
import feedparser
import sqlite3
import streamlit as st
import os
from bs4 import BeautifulSoup
from pathlib import Path
import traceback
from urllib.parse import urlparse, urljoin
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import threading

# API configuration - getting from environment variables for cloud security
PPLX_API_KEY = os.environ.get("PPLX_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

# Updated list of cybersecurity news sources to include both websites and RSS feeds
SOURCES = [
    {"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "priority": "high", "type": "web"},
    {"url": "https://github.com/CVEProject/cvelistV5/tree/main/cves", "priority": "high", "type": "web"},
    {"url": "https://www.sans.org/blog/feed/", "priority": "high", "type": "rss"},
    {"url": "https://isc.sans.edu/diary.xml", "priority": "high", "type": "rss"},
    {"url": "https://www.cisa.gov/cybersecurity-advisories/feed", "priority": "high", "type": "rss"},
    {"url": "https://www.bleepingcomputer.com/feed/", "priority": "high", "type": "rss"},
    {"url": "https://securelist.com/feed/", "priority": "high", "type": "rss"},
    {"url": "https://www.trendmicro.com/en_us/research/rss.xml", "priority": "high", "type": "rss"},
    {"url": "https://blog.malwarebytes.com/feed/", "priority": "high", "type": "rss"},
    {"url": "https://cofense.com/blog/feed/", "priority": "high", "type": "rss"},  # Updated Cofense URL
    
    # Medium priority sources
    {"url": "https://www.zdnet.com/topic/security/rss.xml", "priority": "medium", "type": "rss"},
    {"url": "https://www.bitdefender.com/blog/api/rss/labs/", "priority": "medium", "type": "rss"},
    {"url": "https://thehackernews.com/feeds/posts/default", "priority": "medium", "type": "rss"},
    {"url": "https://krebsonsecurity.com/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://gbhackers.com/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://blog.talosintelligence.com/feeds/posts/default", "priority": "medium", "type": "rss"},
    {"url": "https://www.crowdstrike.com/blog/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://sysdig.com/blog/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://research.checkpoint.com/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://nakedsecurity.sophos.com/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://unit42.paloaltonetworks.com/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://www.horizon3.ai/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://www.mandiant.com/resources/blog/feed", "priority": "medium", "type": "rss"},
    {"url": "https://www.sentinelone.com/blog/feed/", "priority": "medium", "type": "rss"},
    {"url": "https://aws.amazon.com/security/security-bulletins/rss/", "priority": "medium", "type": "rss"}
]

# List of entries to exclude (e.g., newsletters, weekly digests, etc.)
EXCLUDED_KEYWORDS = [
    "week in security", 
    "weekly digest", 
    "security roundup", 
    "security monthly", 
    "security weekly", 
    "security insights",
    "newsletter",
    "webinar",
    "podcast episode",
    "this week in",
    "monthly roundup",
    "career",
    "hiring",
    "job posting"
]

# List of keywords for different content types (expanded beyond just incidents)
CONTENT_TYPES = {
    "vulnerability": ["vulnerability", "flaw", "weakness", "exploit", "CVE", "zero-day", "zero day"],
    "attack": ["attack", "breach", "hack", "compromise", "ransomware", "malware", "phishing", "leaked"],
    "patch": ["patch", "update", "fix", "security update", "hotfix", "advisory"],
    "product_release": ["release", "launches", "announces", "new version", "upgraded", "unveiled"],
    "security_measure": ["security measure", "best practice", "hardening", "mitigate", "prevent", "implement"]
}

# List of unofficial domains to exclude
UNOFFICIAL_DOMAINS = [
    "youtube.com", "pinterest.com", "facebook.com", "twitter.com", "instagram.com",
    "tiktok.com", "linkedin.com", "reddit.com", "medium.com", "quora.com",
    "slideshare.net", "flickr.com", "vimeo.com", "dailymotion.com"
]

# List of major vendors to track - all with equal priority
VENDOR_PRIORITIES = {}  # Empty dictionary since we're not using vendor priorities anymore

# Headers to mimic a browser request
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# Set up database
def setup_database():
    """Set up SQLite database for caching results"""
    db_path = Path("cybersecurity_incidents.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT,
        link TEXT,
        date TEXT,
        description TEXT,
        source TEXT,
        source_name TEXT,
        type TEXT,
        severity TEXT,
        severity_score INTEGER,
        vendors TEXT,
        cve_ids TEXT,
        impact TEXT,
        mitigation TEXT,
        created_at TEXT,
        full_content TEXT,
        hyperlinks TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cache_info (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT
    )
    ''')
    
    conn.commit()
    return conn

def store_incident(conn, incident):
    """Store an incident in the database"""
    cursor = conn.cursor()
    
    # Convert lists to JSON strings
    vendors_json = json.dumps(incident.get('vendors', []))
    cve_ids_json = json.dumps(incident.get('cve_ids', []))
    hyperlinks_json = json.dumps(incident.get('hyperlinks', []))
    
    try:
        cursor.execute('''
        INSERT OR REPLACE INTO incidents 
        (id, title, link, date, description, source, source_name, type, severity, severity_score, 
        vendors, cve_ids, impact, mitigation, created_at, full_content, hyperlinks)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident['id'],
            incident['title'],
            incident.get('link', ''),
            incident.get('date', ''),
            incident.get('description', ''),
            incident.get('source', ''),
            incident.get('source_name', ''),
            incident.get('type', 'unknown'),
            incident.get('severity', 'medium'),
            incident.get('severity_score', 50),
            vendors_json,
            cve_ids_json,
            incident.get('impact', ''),
            incident.get('mitigation', ''),
            datetime.datetime.now().isoformat(),
            incident.get('full_content', ''),
            hyperlinks_json
        ))
        conn.commit()
    except Exception as e:
        print(f"Error storing incident in database: {e}")

def get_cached_incidents(conn, days_to_look_back):
    """Get cached incidents from the database"""
    cursor = conn.cursor()
    cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=days_to_look_back)).isoformat()
    
    try:
        cursor.execute('''
        SELECT * FROM incidents
        WHERE created_at > ?
        ORDER BY severity_score DESC
        ''', (cutoff_date,))
        
        rows = cursor.fetchall()
        
        # Convert rows to dictionaries
        incidents = []
        for row in rows:
            incident = {
                'id': row[0],
                'title': row[1],
                'link': row[2],
                'date': row[3],
                'description': row[4],
                'source': row[5],
                'source_name': row[6],
                'type': row[7],
                'severity': row[8],
                'severity_score': row[9],
                'vendors': json.loads(row[10]),
                'cve_ids': json.loads(row[11]),
                'impact': row[12],
                'mitigation': row[13],
                'created_at': row[14],
                'full_content': row[15] if len(row) > 15 else '',
                'hyperlinks': json.loads(row[16]) if len(row) > 16 and row[16] else []
            }
            
            # Calculate vendor priority score
            incident['vendor_priority'] = calculate_vendor_priority(incident['vendors'])
            
            incidents.append(incident)
        
        return incidents
    except Exception as e:
        print(f"Error retrieving cached incidents: {e}")
        return []

def calculate_vendor_priority(vendors):
    """Calculate a priority score based on affected vendors - now returns 0 since we're using GPT analysis"""
    return 0

def is_cache_fresh(conn, hours=0):
    """Check if the cache is fresh (updated within the last X hours)"""
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT value, updated_at FROM cache_info WHERE key = 'last_update'")
        result = cursor.fetchone()
        
        if not result:
            return False
        
        last_update = datetime.datetime.fromisoformat(result[1])
        now = datetime.datetime.now()
        
        # Check if the cache was updated in the last X hours
        return (now - last_update).total_seconds() < hours * 3600
    except Exception:
        return False

def update_cache_timestamp(conn):
    """Update the cache timestamp"""
    cursor = conn.cursor()
    now = datetime.datetime.now().isoformat()
    
    cursor.execute('''
    INSERT OR REPLACE INTO cache_info (key, value, updated_at)
    VALUES (?, ?, ?)
    ''', ('last_update', 'true', now))
    
    conn.commit()

def format_incident_card(incident, idx):
    """Format a single incident as an HTML card with summary and hyperlinks."""
    severity_class = "high-severity" if incident.get("severity_score", 0) > 80 else "medium-severity" if incident.get("severity_score", 0) > 50 else "low-severity"
    
    # Format date nicely if available
    display_date = incident.get('date', 'Unknown date')
    if display_date and display_date != 'Unknown date':
        try:
            date_obj = None
            date_formats = ["%Y-%m-%d", "%d %b %Y", "%B %d, %Y", "%b %d, %Y"]
            for fmt in date_formats:
                try:
                    date_obj = datetime.datetime.strptime(display_date, fmt)
                    break
                except ValueError:
                    continue
            
            if date_obj:
                display_date = date_obj.strftime("%B %d, %Y")
        except:
            pass
    
    # Clean and ensure the link is properly escaped and valid
    try:
        link = incident.get('link', '#')
        if not link or not link.startswith(('http://', 'https://')):
            link = '#'
            link_text = "Link unavailable"
        else:
            link_text = link
        
        link_html = f"<div class='incident-link-text'><a href='{link}' target='_blank' rel='noopener noreferrer' class='incident-link'>{link_text}</a></div>"
    except:
        link_html = "<div class='incident-link-text'>Link unavailable</div>"
    
    # Get the summary if available
    summary = incident.get('summary', '')
    if not summary and incident.get('description'):
        # Use description as fallback if no summary
        summary = incident.get('description')
    
    summary_html = f"<div class='incident-summary'>{summary}</div>" if summary else ""
    
    # Format hyperlinks
    hyperlinks_html = ""
    if incident.get('hyperlinks') and len(incident.get('hyperlinks', [])) > 0:
        # Get unique hyperlinks
        unique_hyperlinks = []
        seen_urls = set()
        for link in incident.get('hyperlinks', []):
            # Normalize URL for comparison
            normalized_url = link.rstrip('/')
            if normalized_url not in seen_urls and normalized_url != incident.get('link', '').rstrip('/'):
                seen_urls.add(normalized_url)
                unique_hyperlinks.append(link)
        
        # Show unique hyperlinks
        if unique_hyperlinks:
            hyperlinks_html = "<div class='hyperlinks-container'><strong>Hyper Links:</strong><ul class='hyperlinks-list'>"
            for link in unique_hyperlinks[:10]:  # Limit to top 10 hyperlinks
                try:
                    hyperlinks_html += f"<li><a href='{link}' target='_blank' rel='noopener noreferrer'>{link}</a></li>"
                except:
                    continue
            hyperlinks_html += "</ul></div>"
    
    # Create the full HTML for the incident card
    html = f"""
    <div class="incident-card {severity_class}">
        <div class="incident-header">
            <span class="incident-number">{idx}.</span> {incident['title']}
        </div>
        <div class="incident-meta">
            Source: {incident.get('source_name', 'Unknown Source')} | Published: {display_date}
        </div>
        {summary_html}
        <div class="incident-link-container">
            {link_html}
        </div>
        {hyperlinks_html}
    </div>
    """
    return html

# Utility functions
def get_current_date():
    return datetime.datetime.now().strftime("%Y-%m-%d")

def get_date_n_days_back(n):
    past_date = datetime.datetime.now() - datetime.timedelta(days=n)
    return past_date.strftime("%Y-%m-%d")

def make_request(url):
    try:
        # Skip CVE.org URLs if they're causing timeouts
        if 'cve.org' in url.lower():
            return None
            
        time.sleep(random.uniform(0.5, 2))  # Reduced delay for better performance
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def is_valid_source(url):
    """Check if the URL is from an official source (not social media, etc.)"""
    try:
        domain = url.split('//')[1].split('/')[0].lower()
        return not any(unofficial in domain for unofficial in UNOFFICIAL_DOMAINS)
    except:
        return True  # If we can't parse the URL, we'll include it by default

def is_excluded_content(title, description=""):
    """Check if the article is a weekly digest, newsletter, etc. that should be excluded"""
    combined_text = (title + " " + description).lower()
    return any(keyword.lower() in combined_text for keyword in EXCLUDED_KEYWORDS)

def extract_date_from_url(url):
    """Try to extract a date from the URL if present"""
    # This function looks for date patterns in URLs like /2024/03/19/ or similar
    try:
        # Look for year/month/day patterns in the URL
        date_patterns = [
            r'/(\d{4})/(\d{1,2})/(\d{1,2})/',  # /2024/03/19/
            r'(\d{4})-(\d{1,2})-(\d{1,2})',    # 2024-03-19
            r'(\d{4})_(\d{1,2})_(\d{1,2})',    # 2024_03_19
            r'/(\d{4})(\d{2})(\d{2})/'         # /20240319/
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, url)
            if match:
                year, month, day = map(int, match.groups())
                # Validate date components
                if 2000 <= year <= 2030 and 1 <= month <= 12 and 1 <= day <= 31:
                    return f"{year}-{month:02d}-{day:02d}"
        
        return None
    except:
        return None

def is_within_date_range(date_str, days_to_look_back):
    """Check if a date string is within the specified range from today"""
    try:
        # Common date formats to try
        formats = [
            "%Y-%m-%d",                  # 2025-03-20
            "%d %b %Y",                  # 20 Mar 2025
            "%B %d, %Y",                 # March 20, 2025
            "%b %d, %Y",                 # Mar 20, 2025
            "%d/%m/%Y",                  # 20/03/2025
            "%m/%d/%Y",                  # 03/20/2025
            "%d-%m-%Y",                  # 20-03-2025
            "%Y.%m.%d",                  # 2025.03.20
            "%d.%m.%Y",                  # 20.03.2025
            "%a, %d %b %Y",              # Thu, 20 Mar 2025
            "%A, %B %d, %Y",             # Thursday, March 20, 2025
        ]
        
        # Try to parse the date with each format
        parsed_date = None
        for fmt in formats:
            try:
                parsed_date = datetime.datetime.strptime(date_str, fmt)
                break
            except (ValueError, TypeError):
                continue
        
        # If none of the formats worked, try to find a date pattern in the string
        if not parsed_date:
            # Look for patterns like "Published: Mar 18, 2025" or "Posted on March 20"
            date_patterns = [
                r'(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})',
                r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}',
                r'\d{4}-\d{2}-\d{2}',
                r'\d{1,2}/\d{1,2}/\d{4}',
                r'\d{1,2}-\d{1,2}-\d{4}'
            ]
            
            for pattern in date_patterns:
                match = re.search(pattern, date_str, re.IGNORECASE)
                if match:
                    extracted_date = match.group(0)
                    for fmt in formats:
                        try:
                            parsed_date = datetime.datetime.strptime(extracted_date, fmt)
                            break
                        except (ValueError, TypeError):
                            continue
                    if parsed_date:
                        break
        
        # If we still don't have a valid date, check if it says "today", "yesterday", etc.
        if not parsed_date:
            today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            
            if re.search(r'\btoday\b', date_str, re.IGNORECASE):
                parsed_date = today
            elif re.search(r'\byesterday\b', date_str, re.IGNORECASE):
                parsed_date = today - datetime.timedelta(days=1)
            elif match := re.search(r'(\d+)\s+days?\s+ago', date_str, re.IGNORECASE):
                days_ago = int(match.group(1))
                parsed_date = today - datetime.timedelta(days=days_ago)
            elif match := re.search(r'(\d+)\s+hours?\s+ago', date_str, re.IGNORECASE):
                parsed_date = today  # If it's just hours ago, it's from today
        
        if parsed_date:
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days_to_look_back)
            return parsed_date >= cutoff_date
        
        return False  # If we couldn't parse the date, we'll exclude it
        
    except Exception as e:
        # If there's any error in parsing, we'll log it and include the article by default
        print(f"Error parsing date '{date_str}': {e}")
        return True

def format_date_string(date_str):
    """Try to format a date string into a consistent format (YYYY-MM-DD)"""
    try:
        # Common date formats to try
        formats = [
            "%Y-%m-%d",                  # 2025-03-20
            "%d %b %Y",                  # 20 Mar 2025
            "%B %d, %Y",                 # March 20, 2025
            "%b %d, %Y",                 # Mar 20, 2025
            "%d/%m/%Y",                  # 20/03/2025
            "%m/%d/%Y",                  # 03/20/2025
            "%d-%m-%Y",                  # 20-03-2025
            "%Y.%m.%d",                  # 2025.03.20
            "%d.%m.%Y",                  # 20.03.2025
            "%a, %d %b %Y",              # Thu, 20 Mar 2025
            "%A, %B %d, %Y",             # Thursday, March 20, 2025
        ]
        
        # Try to parse the date with each format
        for fmt in formats:
            try:
                parsed_date = datetime.datetime.strptime(date_str, fmt)
                return parsed_date.strftime("%Y-%m-%d")  # Return in standard format
            except (ValueError, TypeError):
                continue
        
        # If none of the formats worked, look for date patterns
        date_patterns = [
            r'(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})',
            r'((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})',
            r'(\d{4}-\d{2}-\d{2})',
            r'(\d{1,2}/\d{1,2}/\d{4})',
            r'(\d{1,2}-\d{1,2}-\d{4})'
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, date_str, re.IGNORECASE)
            if match:
                extracted_date = match.group(1)
                for fmt in formats:
                    try:
                        parsed_date = datetime.datetime.strptime(extracted_date, fmt)
                        return parsed_date.strftime("%Y-%m-%d")
                    except (ValueError, TypeError):
                        continue
        
        # If we get here, just return the original string
        return date_str
        
    except Exception:
        return date_str

def extract_cves_from_text(text):
    """Extract CVE IDs from text"""
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return list(set(re.findall(cve_pattern, text)))

def extract_vendors_from_text(text):
    """Extract vendor names from text"""
    vendors = []
    for vendor in VENDOR_PRIORITIES.keys():
        if vendor.lower() in text.lower():
            vendors.append(vendor)
    return vendors

def extract_articles_from_rss(source_url, days_to_look_back):
    """Extract articles from an RSS feed"""
    articles = []
    try:
        feed = feedparser.parse(source_url)
        
        for entry in feed.entries:
            title = entry.title
            link = entry.link
            
            # Skip if the article should be excluded
            if is_excluded_content(title, entry.get('summary', '')):
                continue
            
            # Get published date
            date = entry.get('published', entry.get('updated', 'Unknown date'))
            
            # Try to extract date from URL if no date is available
            if date == "Unknown date":
                url_date = extract_date_from_url(link)
                if url_date:
                    date = url_date
            
            # Check if article is within our date range
            if date != "Unknown date" and not is_within_date_range(date, days_to_look_back):
                continue
            
            # Skip if the link is from an unofficial source
            if link and not is_valid_source(link):
                continue
            
            description = entry.get('summary', '')
            
            # Try to extract a more readable date
            actual_date = None
            if date != "Unknown date":
                try:
                    actual_date = format_date_string(date)
                except:
                    actual_date = date
            
            # Extract source name from URL
            source_name = source_url.split('//')[-1].split('/')[0].replace('www.', '')
            
            articles.append({
                "title": title,
                "link": link,
                "date": actual_date or date,
                "description": description[:300] + "..." if len(description) > 300 else description,
                "source": source_url,
                "source_name": source_name
            })
    except Exception as e:
        print(f"Error extracting articles from RSS feed {source_url}: {e}")
    
    return articles

def extract_articles_from_web(html_content, source_url, days_to_look_back):
    """Extract articles from a web page"""
    articles = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove unwanted elements like scripts, styles, navigation, etc.
        for element in soup.select('script, style, nav, header, footer, .sidebar, .comments, .related-posts, .advertisement, iframe'):
            if element:
                element.decompose()
        
        # Look for article tags, divs with article class, or common blog post structures
        potential_articles = (
            soup.find_all('article') or 
            soup.find_all('div', class_=['post', 'entry', 'blog-post', 'news-item']) or
            soup.select('.post, .article, .blog-item, .news-entry')
        )
        
        # If no structure found, look for headings with links
        if not potential_articles:
            potential_articles = soup.select('h1 a, h2 a, h3 a')
        
        # Don't limit the number of articles per source
        for article in potential_articles:
            title_elem = article.find('h1') or article.find('h2') or article.find('h3') or article.find('a')
            
            if title_elem:
                title = title_elem.text.strip()
                
                # Skip if the article should be excluded
                if is_excluded_content(title):
                    continue
                
                link = None
                
                # Try to find the link
                if title_elem.name == 'a':
                    link = title_elem.get('href')
                else:
                    link_elem = title_elem.find('a')
                    if link_elem:
                        link = link_elem.get('href')
                
                # Make relative URLs absolute
                if link and not link.startswith('http'):
                    if link.startswith('/'):
                        base_url = '/'.join(source_url.split('/')[:3])  # Get domain
                        link = base_url + link
                    else:
                        link = source_url + link if source_url.endswith('/') else source_url + '/' + link
                
                # Skip if the link is from an unofficial source
                if link and not is_valid_source(link):
                    continue
                
                # Try to find date
                date_elem = article.find('time') or article.select_one('.date, .meta-date, .published, .post-date')
                date = date_elem.text.strip() if date_elem else "Unknown date"
                
                # Extract published date from data attributes if available
                if not date_elem:
                    date_attrs = ['data-date', 'data-published', 'datetime', 'date-time']
                    for attr in date_attrs:
                        date_val = article.get(attr) or (date_elem and date_elem.get(attr))
                        if date_val:
                            date = date_val
                            break
                
                 # Try to extract date from URL if no date is available
                if date == "Unknown date" and link:
                    url_date = extract_date_from_url(link)
                    if url_date:
                        date = url_date
                
                # Try to find description/summary
                desc_elem = article.find('p') or article.select_one('.excerpt, .summary, .description')
                description = desc_elem.text.strip() if desc_elem else ""
                
                # Skip if the article should be excluded based on description
                if is_excluded_content("", description):
                    continue
                
                # Check if article is within our date range
                if date != "Unknown date" and not is_within_date_range(date, days_to_look_back):
                    continue
                
                if title and link:
                    # Get actual date string from the page if possible
                    actual_date = None
                    if date != "Unknown date":
                        try:
                            # Try to extract just the date part in a standardized format
                            actual_date = format_date_string(date)
                        except:
                            actual_date = date
                    
                    articles.append({
                        "title": title,
                        "link": link,
                        "date": actual_date or date,
                        "description": description[:300] + "..." if len(description) > 300 else description,
                        "source": source_url,
                        "source_name": source_url.split('//')[-1].split('/')[0].replace('www.', '')
                    })
        
    except Exception as e:
        print(f"Error extracting articles from {source_url}: {e}")
    
    return articles

def scrape_full_content(url):
    """Scrape the full content of an article including all text, hyperlinks, and related articles"""
    try:
        # Make request to the article URL
        html_content = make_request(url)
        if not html_content:
            return {"content": "", "hyperlinks": [], "related_articles": [], "published_date": None}
        
        # Parse HTML content
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Special handling for CVE pages
        if 'cve.org' in url.lower():
            # Try to find the published date
            published_date = None
            date_elements = soup.select('.col-lg-9 td, .col-lg-9 th')  # Adjust selectors based on CVE page structure
            for element in date_elements:
                if 'Published:' in element.get_text():
                    date_text = element.find_next_sibling('td')
                    if date_text:
                        published_date = date_text.get_text().strip()
                        break
            
            # Extract CVE content
            cve_content = []
            content_sections = soup.select('.col-lg-9 table, .vulnerability-info, .cve-record')
            for section in content_sections:
                text = section.get_text(strip=True)
                if text:
                    cve_content.append(text)
            
            return {
                "content": '\n'.join(cve_content),
                "hyperlinks": [],  # CVE pages typically don't have relevant hyperlinks
                "related_articles": [],
                "published_date": published_date
            }
        
        # Remove unwanted elements like scripts, styles, and navigation
        for element in soup.select('script, style, nav, header, footer, .sidebar, .comments, .advertisement, iframe'):
            if element:
                element.decompose()
        
        # Find article content (try different common selectors)
        article_content = None
        content_selectors = [
            'article', '.post-content', '.entry-content', '.article-content', '.content', 
            '.post-body', '.story-body', '.story', 'main', '#content', '[itemprop="articleBody"]',
            '.news-content', '.blog-content'
        ]
        
        for selector in content_selectors:
            article_content = soup.select_one(selector)
            if article_content and len(article_content.get_text(strip=True)) > 200:
                break
        
        # If no content found with selectors, use the body with major elements removed
        if not article_content or len(article_content.get_text(strip=True)) < 200:
            article_content = soup.body
        
        # Try to find published date
        published_date = None
        date_selectors = [
            'time', '[itemprop="datePublished"]', '.published', '.post-date', '.entry-date',
            '.article-date', '.date', '[property="article:published_time"]'
        ]
        
        for selector in date_selectors:
            date_element = soup.select_one(selector)
            if date_element:
                # Check for datetime attribute first
                published_date = date_element.get('datetime', date_element.get('content', ''))
                if not published_date:
                    published_date = date_element.get_text().strip()
                if published_date:
                    break
        
        # Clean the content by removing extra whitespace
        if not article_content:
            return {"content": "", "hyperlinks": [], "related_articles": [], "published_date": published_date}
            
        # Extract text content, preserve basic structure
        paragraphs = []
        for p in article_content.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li']):
            text = p.get_text(strip=True)
            if text and len(text) > 20:  # Ignore short fragments
                if p.name.startswith('h'):
                    paragraphs.append(f"<strong>{text}</strong>")
                else:
                    paragraphs.append(text)
        
        full_text = '<p>' + '</p><p>'.join(paragraphs) + '</p>'
        
        # First, extract related articles with high priority
        related_articles = []
        related_hyperlinks = set()  # Use set to avoid duplicates
        
        # Expanded list of related article selectors
        related_selectors = [
            '.related-articles', '.related-posts', '.similar-articles', '#related-articles',
            '.see-also', '.recommended', '.more-like-this', '.suggested-articles',
            '[data-related]', '[data-recommended]', '.related-content', '.article-suggestions',
            '.further-reading', '.read-more', '.also-read', '.similar-stories'
        ]
        
        # First try specific related article sections
        related_sections = soup.select(', '.join(related_selectors))
        
        if not related_sections:
            # Try finding related articles in the sidebar or at the bottom
            related_sections = soup.select('.sidebar, .post-footer, .article-footer, .content-footer')
        
        base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url))
        
        # Process related articles first
        for section in related_sections:
            links = section.find_all('a') if section else []
            for link in links:
                href = link.get('href', '')
                title = link.get_text(strip=True)
                
                if href and title and len(title) > 10:  # Skip very short titles
                    # Make relative URLs absolute
                    if not href.startswith(('http://', 'https://')):
                        href = urljoin(base_url, href)
                    
                    # Skip if it's not a valid article link
                    if any(term in href.lower() for term in ['share', 'twitter', 'facebook', 'email', 'print', 'comment']):
                        continue
                    
                    # Normalize URL
                    normalized_href = href.rstrip('/')
                    if normalized_href not in related_hyperlinks:
                        related_hyperlinks.add(normalized_href)
                        related_articles.append({
                            'title': title,
                            'link': href
                        })
        
        # Now extract remaining hyperlinks from the content
        content_hyperlinks = []
        
        # Find all links in the article content
        for a_tag in article_content.find_all('a', href=True):
            link = a_tag['href']
            
            # Skip internal page anchors and javascript links
            if link.startswith('#') or link.startswith('javascript:'):
                continue
                
            # Make relative URLs absolute
            if not link.startswith(('http://', 'https://')):
                link = urljoin(base_url, link)
            
            # Skip social media and non-security related links
            if is_valid_source(link) and not any(term in link.lower() for term in ['share', 'twitter', 'facebook', 'email', 'print', 'comment']):
                # Normalize URL by removing trailing slash
                normalized_link = link.rstrip('/')
                # Only add if not already in related articles
                if normalized_link not in related_hyperlinks:
                    content_hyperlinks.append(normalized_link)
        
        # Combine hyperlinks with related articles first, then content links
        all_hyperlinks = list(related_hyperlinks) + content_hyperlinks
        
        return {
            "content": full_text,
            "hyperlinks": all_hyperlinks,
            "related_articles": related_articles,
            "published_date": published_date
        }
        
    except Exception as e:
        print(f"Error scraping content from {url}: {e}")
        traceback.print_exc()
        return {"content": "", "hyperlinks": [], "related_articles": [], "published_date": None}

def enhance_with_pplx(url, title, content=""):
    """Use PPLX API to extract and analyze content from complex websites"""
    if not PPLX_API_KEY:
        return {"content": content, "hyperlinks": [], "summary": ""}
        
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {PPLX_API_KEY}"
        }
        
        # Get a detailed summary
        summary_payload = {
            "model": "llama-3.1-sonar-small-128k-online",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity content summarizer. Provide a detailed summary of the article focusing on key impacts, technical details, and consequences. Include specific numbers, systems affected, and any financial or operational impacts mentioned."
                },
                {
                    "role": "user",
                    "content": f"Provide a detailed summary of this cybersecurity article:\nTitle: {title}\nContent: {content[:4000]}"
                }
            ],
            "max_tokens": 500
        }
        
        summary_response = requests.post(
            "https://api.perplexity.ai/chat/completions",
            headers=headers,
            json=summary_payload,
        )
        
        summary = ""
        if summary_response.status_code == 200:
            result = summary_response.json()
            summary = result["choices"][0]["message"]["content"].strip()
        
        # Then get the full content analysis
        content_payload = {
            "model": "llama-3.1-sonar-small-128k-online",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity content extraction assistant. Extract the main content from the provided URL. Include all relevant technical details about security issues."
                },
                {
                    "role": "user",
                    "content": f"Extract the main content from this cybersecurity article: {url}\nTitle: {title}"
                }
            ],
            "max_tokens": 4000
        }
        
        content_response = requests.post(
            "https://api.perplexity.ai/chat/completions",
            headers=headers,
            json=content_payload,
        )
        
        if content_response.status_code == 200:
            result = content_response.json()
            extracted_content = result["choices"][0]["message"]["content"]
            
            # Extract hyperlinks from PPLX response
            hyperlinks = []
            link_pattern = r'https?://[^\s)\]"]+'
            hyperlinks = re.findall(link_pattern, extracted_content)
            
            # Clean up content and links
            cleaned_content = re.sub(r'(https?://[^\s)\]"]+)', '', extracted_content)
            
            return {
                "content": cleaned_content if cleaned_content else content,
                "hyperlinks": list(set(hyperlinks)) if hyperlinks else [],
                "summary": summary
            }
        else:
            return {"content": content, "hyperlinks": [], "summary": summary}
            
    except Exception as e:
        print(f"Error using PPLX API: {e}")
        return {"content": content, "hyperlinks": [], "summary": ""}

def analyze_with_openai(title, content, hyperlinks):
    """Use OpenAI to analyze and summarize content"""
    if not OPENAI_API_KEY or not content:
        return {"impact": "", "mitigation": "", "severity_score": 50}
        
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst assistant. Analyze the provided content from a security article and determine its importance and severity. Consider factors like: potential impact, number of affected systems/users, ease of exploitation, availability of patches/mitigations, and real-world exploitation status."
                },
                {
                    "role": "user",
                    "content": f"Title: {title}\n\nContent: {content[:4000]}...\n\nAnalyze this cybersecurity article and provide:\n1) Impact assessment (who is affected and how severely)\n2) Mitigation recommendations\n3) A severity score from 0-100 where higher means more severe. Consider:\n- Potential impact (data breach, system compromise, etc.)\n- Number of affected systems/users\n- Ease of exploitation\n- Availability of patches/mitigations\n- Evidence of active exploitation\n- Technical complexity of the issue"
                }
            ],
            "max_tokens": 1000
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
        )
        
        if response.status_code == 200:
            result = response.json()
            analysis = result["choices"][0]["message"]["content"]
            
            # Extract severity score
            severity_score = 50  # Default medium
            score_match = re.search(r'severity score[:\s]*(\d+)', analysis, re.IGNORECASE)
            if score_match:
                try:
                    severity_score = int(score_match.group(1))
                    # Ensure in range 0-100
                    severity_score = max(0, min(100, severity_score))
                except:
                    pass
            
            # Extract impact and mitigation using regex
            impact = ""
            impact_match = re.search(r'impact[:\s]*(.*?)(?=mitigation|\Z)', analysis, re.IGNORECASE | re.DOTALL)
            if impact_match:
                impact = impact_match.group(1).strip()
            
            mitigation = ""
            mitigation_match = re.search(r'mitigation[:\s]*(.*?)(?=severity|\Z)', analysis, re.IGNORECASE | re.DOTALL)
            if mitigation_match:
                mitigation = mitigation_match.group(1).strip()
            
            return {
                "impact": impact,
                "mitigation": mitigation,
                "severity_score": severity_score
            }
        else:
            return {"impact": "", "mitigation": "", "severity_score": 50}
            
    except Exception as e:
        print(f"Error using OpenAI API: {e}")
        return {"impact": "", "mitigation": "", "severity_score": 50}

def generate_article_id(article):
    """Generate a unique ID for an article based on its title and link"""
    unique_string = f"{article['title']}{article.get('link', '')}"
    return hashlib.md5(unique_string.encode()).hexdigest()

def process_source(source, days_to_look_back=7):
    """Process a single source and return articles"""
    source_url = source["url"]
    source_type = source["type"]
    priority = source["priority"]
    
    # Skip CVE.org sources
    if 'cve.org' in source_url.lower():
        return []
    
    articles = []
    try:
        if source_type == "rss":
            articles = extract_articles_from_rss(source_url, days_to_look_back)
        elif source_type == "web":
            html_content = make_request(source_url)
            if html_content:
                articles = extract_articles_from_web(html_content, source_url, days_to_look_back)
        
        # Process each article
        processed_articles = []
        for article in articles:
            # Skip articles from CVE.org
            if article.get('link') and 'cve.org' in article.get('link').lower():
                continue
                
            # Try to scrape full content to get published date if not available
            if article.get('date') == 'Unknown date' and article.get('link'):
                scraped_data = scrape_full_content(article['link'])
                if scraped_data.get('published_date'):
                    article['date'] = format_date_string(scraped_data['published_date'])
            
            # Skip articles without a valid date
            if article.get('date') == 'Unknown date':
                continue
            
            # Add source information and generate unique ID
            article["source_priority"] = priority
            article["id"] = generate_article_id(article)
            
            # Determine content type
            article["type"] = determine_content_type(article['title'], article.get('description', ''))
            
            # Extract vendors
            article["vendors"] = extract_vendors_from_text(f"{article['title']} {article.get('description', '')}")
            
            # Extract CVEs
            article["cve_ids"] = extract_cves_from_text(f"{article['title']} {article.get('description', '')}")
            
            # Set default severity based on content type
            if article["type"] == "vulnerability" or article["type"] == "attack":
                article["severity"] = "high"
                article["severity_score"] = 80
            elif article["type"] == "patch":
                article["severity"] = "medium"
                article["severity_score"] = 60
            else:
                article["severity"] = "medium"
                article["severity_score"] = 50
            
            processed_articles.append(article)
            
    except Exception as e:
        print(f"Error processing source {source_url}: {e}")
        
    return processed_articles

def determine_content_type(title, description=""):
    """Determine the content type based on keywords in the title and description"""
    combined_text = (title + " " + description).lower()
    
    # Check for each content type
    for content_type, keywords in CONTENT_TYPES.items():
        if any(keyword.lower() in combined_text for keyword in keywords):
            return content_type
    
    # Default to vulnerability if we find CVE pattern
    if re.search(r'CVE-\d{4}-\d{4,7}', combined_text):
        return "vulnerability"
        
    # Default to unknown
    return "unknown"

def get_api_enhanced_incidents(incidents, use_api=True):
    """Enhance incidents with API data and content scraping"""
    enhanced_incidents = []
    
    for incident in incidents:
        # Skip if no link available
        if not incident.get('link'):
            enhanced_incidents.append(incident)
            continue
        
        # Attempt to scrape full content using BeautifulSoup
        scraped_data = scrape_full_content(incident['link'])
        
        # If BeautifulSoup failed to get good content and APIs are enabled, try PPLX
        if use_api and (not scraped_data['content'] or len(scraped_data['content']) < 500):
            pplx_data = enhance_with_pplx(
                incident['link'], 
                incident['title'], 
                scraped_data['content']
            )
            
            # Use PPLX data if it's better than what we got from scraping
            if pplx_data['content'] and len(pplx_data['content']) > len(scraped_data['content']):
                incident['full_content'] = pplx_data['content']
                
                # Combine hyperlinks from both sources
                combined_links = list(set(scraped_data['hyperlinks'] + pplx_data['hyperlinks']))
                incident['hyperlinks'] = combined_links
            else:
                incident['full_content'] = scraped_data['content']
                incident['hyperlinks'] = scraped_data['hyperlinks']
        else:
            incident['full_content'] = scraped_data['content']
            incident['hyperlinks'] = scraped_data['hyperlinks']
        
        # Extract additional CVEs and vendors from full content if available
        if incident['full_content']:
            additional_cves = extract_cves_from_text(incident['full_content'])
            if additional_cves:
                incident['cve_ids'] = list(set(incident.get('cve_ids', []) + additional_cves))
                
            additional_vendors = extract_vendors_from_text(incident['full_content'])
            if additional_vendors:
                incident['vendors'] = list(set(incident.get('vendors', []) + additional_vendors))
        
        # Use OpenAI to analyze content if enabled and content is available
        if use_api and incident['full_content'] and len(incident['full_content']) > 200:
            analysis = analyze_with_openai(
                incident['title'],
                incident['full_content'],
                incident['hyperlinks']
            )
            
            if analysis['impact']:
                incident['impact'] = analysis['impact']
                
            if analysis['mitigation']:
                incident['mitigation'] = analysis['mitigation']
                
            if analysis['severity_score'] > 0:
                # Use AI severity score but keep original score if it's higher
                incident['severity_score'] = max(incident.get('severity_score', 0), analysis['severity_score'])
                
                # Update severity label based on score
                if incident['severity_score'] >= 80:
                    incident['severity'] = 'high'
                elif incident['severity_score'] >= 50:
                    incident['severity'] = 'medium'
                else:
                    incident['severity'] = 'low'
        
        enhanced_incidents.append(incident)
    
    return enhanced_incidents

def fetch_incidents(days_to_look_back=7, cache_hours=24, max_incidents=None, use_api=False):
    """Fetch incidents from all sources and cache them"""
    conn = setup_database()
    
    # Check if we have fresh cached results
    if is_cache_fresh(conn, cache_hours):
        incidents = get_cached_incidents(conn, days_to_look_back)
        
        # Sort incidents by severity score only (no vendor priority)
        incidents = sorted(incidents, key=lambda x: x.get('severity_score', 0), reverse=True)
        
        # Limit number of incidents if specified
        if max_incidents and isinstance(max_incidents, int) and max_incidents > 0:
            incidents = incidents[:max_incidents]
            
        conn.close()
        return incidents, len(incidents)
    
    all_articles = []
    sources_processed = 0
    
    # Process all sources in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_source = {executor.submit(process_source, source, days_to_look_back): source for source in SOURCES}
        
        for future in concurrent.futures.as_completed(future_to_source):
            source = future_to_source[future]
            try:
                articles = future.result()
                all_articles.extend(articles)
                sources_processed += 1
            except Exception as e:
                print(f"Error processing source {source['url']}: {e}")
    
    # Group articles by source to ensure distribution
    articles_by_source = {}
    for article in all_articles:
        source = article.get('source_name', '')
        if source not in articles_by_source:
            articles_by_source[source] = []
        articles_by_source[source].append(article)
    
    # Distribute articles across sources
    distributed_articles = []
    while len(distributed_articles) < max_incidents and articles_by_source:
        for source in list(articles_by_source.keys()):
            if articles_by_source[source]:
                article = articles_by_source[source].pop(0)
                distributed_articles.append(article)
                if not articles_by_source[source]:
                    del articles_by_source[source]
            if len(distributed_articles) >= max_incidents:
                break
    
    # Enhance articles with full content scraping and API analysis
    enhanced_articles = get_api_enhanced_incidents(distributed_articles, use_api)
    
    # Sort by severity score from GPT analysis
    enhanced_articles = sorted(enhanced_articles, key=lambda x: x.get('severity_score', 0), reverse=True)
    
    # Store incidents in database
    for article in enhanced_articles:
        store_incident(conn, article)
    
    # Update cache timestamp
    update_cache_timestamp(conn)
    
    conn.close()
    return enhanced_articles, sources_processed

def main():
    # Initialize Streamlit session state
    if 'initialized' not in st.session_state:
        st.session_state.initialized = True
        st.session_state.articles = []
        st.session_state.shown_incident_ids = set()  # Track shown incident IDs
        st.session_state.all_fetched_articles = []   # Store all fetched articles
        st.session_state.last_update = None
        st.session_state.processing = False

    st.set_page_config(page_title="Cybersecurity Incidents Monitor", layout="wide")
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .stSlider > div > div > div > div {
        background-color: #FF5555;
    }
    .stSlider > div > div > div > div > div {
        color: white;
    }
    .incident-card {
        background-color: #f9f9f9;
        border-radius: 5px;
        padding: 15px;
        margin-bottom: 15px;
        border-left: 5px solid #ccc;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .high-severity {
        border-left: 5px solid #FF5555;
    }
    .medium-severity {
        border-left: 5px solid #FFA500;
    }
    .low-severity {
        border-left: 5px solid #5CB85C;
    }
    .incident-header {
        font-size: 18px;
        font-weight: bold;
        margin-bottom: 10px;
    }
    .incident-meta {
        color: #666;
        font-size: 14px;
        margin-bottom: 10px;
    }
    .incident-summary {
        font-size: 14px;
        line-height: 1.4;
        color: #333;
        margin: 10px 0;
        padding: 10px;
        background-color: #f5f5f5;
        border-radius: 4px;
    }
    .incident-link-text {
        word-break: break-all;
        font-size: 14px;
    }
    .incident-link-container {
        margin-top: 5px;
        margin-bottom: 10px;
    }
    .incident-number {
        display: inline-block;
        width: 25px;
        color: #777;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("Cybersecurity Incidents Monitor")
    
    # Sidebar controls
    st.sidebar.header("Settings")
    
    # Display last update time from database
    conn = setup_database()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT value, updated_at FROM cache_info WHERE key = 'last_update'")
        result = cursor.fetchone()
        if result:
            last_update_time = datetime.datetime.fromisoformat(result[1])
            st.session_state.last_update = last_update_time
            st.sidebar.info(f"Last update: {last_update_time.strftime('%Y-%m-%d %H:%M')}")
    except Exception:
        pass
    
    use_api = st.sidebar.checkbox("Use AI Analysis (slower but more detailed)", value=True)
    
    # Add navigation buttons in sidebar
    if len(st.session_state.all_fetched_articles) > 0:
        col1, col2 = st.sidebar.columns(2)
        
        with col1:
            if st.button("Previous 10"):
                # Get the current set of shown incident IDs
                current_ids = list(st.session_state.shown_incident_ids)
                if len(current_ids) > 10:
                    # Remove the last 10 IDs from shown_incident_ids
                    for id in current_ids[-10:]:
                        st.session_state.shown_incident_ids.remove(id)
                    
                    # Get the previous 10 articles
                    prev_articles = []
                    for article in st.session_state.all_fetched_articles:
                        if article['id'] in current_ids[-10:]:
                            prev_articles.append(article)
                    
                    if prev_articles:
                        st.session_state.articles = prev_articles
                        st.rerun()
        
        with col2:
            if st.button("Next 10"):
                # Get next 10 unshown incidents
                next_articles = []
                for article in st.session_state.all_fetched_articles:
                    if article['id'] not in st.session_state.shown_incident_ids and len(next_articles) < 10:
                        # Enhance article with full content and hyperlinks if not already done
                        if not article.get('hyperlinks') and article.get('link'):
                            # First try scraping
                            scraped_data = scrape_full_content(article['link'])
                            article['hyperlinks'] = scraped_data['hyperlinks']
                            article['full_content'] = scraped_data['content']
                            
                            # If APIs enabled and scraping didn't get good results, try PPLX
                            if use_api and (not scraped_data['content'] or len(scraped_data['content']) < 500):
                                pplx_data = enhance_with_pplx(
                                    article['link'],
                                    article['title'],
                                    scraped_data['content']
                                )
                                # Combine hyperlinks from both sources
                                if pplx_data['hyperlinks']:
                                    combined_links = list(set(scraped_data['hyperlinks'] + pplx_data['hyperlinks']))
                                    article['hyperlinks'] = combined_links
                                if pplx_data['content']:
                                    article['full_content'] = pplx_data['content']
                        
                        next_articles.append(article)
                        st.session_state.shown_incident_ids.add(article['id'])
                
                if next_articles:
                    st.session_state.articles = next_articles
                    st.rerun()
                else:
                    st.sidebar.warning("No more new incidents available. Please fetch new incidents.")
        
        # Show current position
        total_articles = len(st.session_state.all_fetched_articles)
        shown_count = len(st.session_state.shown_incident_ids)
        current_page = (shown_count - 1) // 10 + 1
        total_pages = (total_articles + 9) // 10
        st.sidebar.info(f"Page {current_page} of {total_pages}")
    else:
        st.sidebar.warning("Please fetch incidents first using the main button.")

    # Set up a fetch button for manual refresh
    if st.button("FETCH CYBERSECURITY INCIDENTS"):
        if not st.session_state.processing:
            st.session_state.processing = True
            # Reset tracking of shown incidents when fetching new ones
            st.session_state.shown_incident_ids = set()
            st.session_state.all_fetched_articles = []
            
            # Create placeholder for dynamic updating
            progress_bar = st.progress(0)
            status_text = st.empty()
            results_count = st.empty()
            results_container = st.container()
            
            # Setup streaming display
            with results_container:
                incident_placeholders = []
                for i in range(10):  # Fixed to 10 placeholders
                    incident_placeholders.append(st.empty())
            
            try:
                # First update the status
                status_text.text("Connecting to sources...")
                
                # Process sources in real-time
                all_articles = []
                sources_processed = 0
                
                # Process sources one by one for streaming effect
                for i, source in enumerate(SOURCES):
                    try:
                        # Update progress
                        progress = (i + 1) / len(SOURCES)
                        progress_bar.progress(progress)
                        status_text.text(f"Processing source {i+1}/{len(SOURCES)}: {source['url']}")
                        
                        # Process the source
                        articles = process_source(source, 7)  # Using fixed 7 days lookback
                        
                        # Enhance articles with hyperlinks immediately
                        for article in articles:
                            if article.get('link'):
                                # First try scraping
                                scraped_data = scrape_full_content(article['link'])
                                article['hyperlinks'] = scraped_data['hyperlinks']
                                article['full_content'] = scraped_data['content']
                                
                                # If APIs enabled and scraping didn't get good results, try PPLX
                                if use_api and (not scraped_data['content'] or len(scraped_data['content']) < 500):
                                    pplx_data = enhance_with_pplx(
                                        article['link'],
                                        article['title'],
                                        scraped_data['content']
                                    )
                                    # Combine hyperlinks from both sources
                                    if pplx_data['hyperlinks']:
                                        combined_links = list(set(scraped_data['hyperlinks'] + pplx_data['hyperlinks']))
                                        article['hyperlinks'] = combined_links
                                    if pplx_data['content']:
                                        article['full_content'] = pplx_data['content']
                        
                        all_articles.extend(articles)
                        sources_processed += 1
                        
                        # Update counter in real time
                        results_count.text(f"Found {len(all_articles)} articles so far...")
                        
                        # If we have new articles, process and display them
                        if articles:
                            # Sort what we have so far by severity score
                            temp_sorted = sorted(all_articles, key=lambda x: x.get('severity_score', 0), reverse=True)
                            
                            # Show top 10 articles so far
                            displayed_count = min(len(temp_sorted), 10)
                            for idx in range(displayed_count):
                                incident_placeholders[idx].markdown(
                                    format_incident_card(temp_sorted[idx], idx + 1),
                                    unsafe_allow_html=True
                                )
                                
                    except Exception as e:
                        status_text.text(f"Error processing {source['url']}: {str(e)}")
                        time.sleep(1)
                
                # Final processing of top 10 articles
                status_text.text("Processing final incidents...")
                
                # Sort all articles by severity score
                final_articles = sorted(all_articles, key=lambda x: x.get('severity_score', 0), reverse=True)
                
                # Store all fetched articles
                st.session_state.all_fetched_articles = final_articles
                
                # Store shown incident IDs
                st.session_state.shown_incident_ids = set()
                for article in final_articles[:10]:
                    st.session_state.shown_incident_ids.add(article['id'])
                
                # Store in session state
                st.session_state.articles = final_articles[:10]
                
                # Clear status messages
                status_text.empty()
                results_count.empty()
                progress_bar.empty()
                
                # Force a rerun to show the navigation buttons
                st.rerun()
                    
            except Exception as e:
                st.error(f"An error occurred while fetching incidents: {str(e)}")
                st.info("Please try again or check your internet connection.")
            
            finally:
                st.session_state.processing = False
    else:
        # Display cached articles if available
        if 'articles' in st.session_state and st.session_state.articles:
            for idx, article in enumerate(st.session_state.articles[:10]):
                st.markdown(
                    format_incident_card(article, idx + 1),
                    unsafe_allow_html=True
                )
        else:
            # Display initial message if no cached results
            st.info("Click the 'FETCH CYBERSECURITY INCIDENTS' button to get the latest security news and incidents.")
    
    # Close database connection
    try:
        conn.close()
    except:
        pass

if __name__ == "__main__":
    main()
