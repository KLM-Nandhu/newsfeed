from bs4 import BeautifulSoup
from bs4.element import Comment
import requests
import csv
import sys
import json
import re
import os
import logging
from datetime import datetime, timedelta
import streamlit as st
import pandas as pd
import base64
from io import BytesIO

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cybersec_incidents.log"),
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
OUTPUT_FILE = "top_incidents.json"
DAYS_AGO = 2  # Default to fetch articles from today and yesterday

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

# RSS Feeds
RSS_FEEDS = [
    "https://www.sans.org/newsletters/at-risk/",
    "https://isc.sans.edu/diaryarchive.html",
    "https://www.zdnet.com/",
    "https://www.bitdefender.com/blog/",
    "https://us-cert.cisa.gov/ncas",
    "https://isc.sans.edu/diaryarchive.html?year=2024&month=10",
    "https://isc.sans.edu/podcast.html",
    "https://aws.amazon.com/security/security-bulletins/?card-body.sort-by=item.additiona[…]-order=desc&awsf.bulletins-flag=*all&awsf.bulletins-year=*all",
    "https://www.bleepingcomputer.com/",
    "https://securelist.com/",
    "https://www.trendmicro.com/en_us/research.html",
    "https://blog.malwarebytes.com/",
    "https://cofense.com/blog/",
    "https://thehackernews.com/",
    "https://krebsonsecurity.com/",
    "https://gbhackers.com/",
    "https://blog.talosintelligence.com/",
    "https://www.crowdstrike.com/blog/",
    "https://sysdig.com/blog/",
    "https://research.checkpoint.com/latest-publications/",
    "https://nakedsecurity.sophos.com/",
    "https://unit42.paloaltonetworks.com/",
    "https://www.horizon3.ai/feed/",
    "https://www.mandiant.com/resources/blog/",
    "https://www.sentinelone.com/blog/",
]

# Convert regular website URLs to RSS feed URLs where possible
RSS_FEED_MAPPINGS = {
    "https://www.sans.org/newsletters/at-risk/": "https://www.sans.org/newsletters/at-risk/rss/",
    "https://isc.sans.edu/diaryarchive.html": "https://isc.sans.edu/rssfeed.xml",
    "https://www.zdnet.com/": "https://www.zdnet.com/news/rss.xml",
    "https://www.bitdefender.com/blog/": "https://www.bitdefender.com/blog/feed/",
    "https://us-cert.cisa.gov/ncas": "https://us-cert.cisa.gov/ncas/all.xml",
    "https://isc.sans.edu/diaryarchive.html?year=2024&month=10": "https://isc.sans.edu/rssfeed.xml",
    "https://isc.sans.edu/podcast.html": "https://isc.sans.edu/podcast.xml",
    "https://aws.amazon.com/security/security-bulletins/?card-body.sort-by=item.additiona[…]-order=desc&awsf.bulletins-flag=*all&awsf.bulletins-year=*all": "https://aws.amazon.com/blogs/security/feed/",
    "https://www.bleepingcomputer.com/": "https://www.bleepingcomputer.com/feed/",
    "https://securelist.com/": "https://securelist.com/feed/",
    "https://www.trendmicro.com/en_us/research.html": "https://feeds.feedburner.com/TrendMicroSimplySecurity",
    "https://blog.malwarebytes.com/": "https://www.malwarebytes.com/blog/feed/index.xml",
    "https://cofense.com/blog/": "https://cofense.com/blog/feed/",
    "https://thehackernews.com/": "https://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/": "https://krebsonsecurity.com/feed/",
    "https://gbhackers.com/": "https://gbhackers.com/feed/",
    "https://blog.talosintelligence.com/": "https://blog.talosintelligence.com/rss/",
    "https://www.crowdstrike.com/blog/": "https://www.crowdstrike.com/blog/feed/",
    "https://sysdig.com/blog/": "https://sysdig.com/blog/feed/",
    "https://research.checkpoint.com/latest-publications/": "https://research.checkpoint.com/feed/",
    "https://nakedsecurity.sophos.com/": "https://nakedsecurity.sophos.com/feed/",
    "https://unit42.paloaltonetworks.com/": "https://unit42.paloaltonetworks.com/feed/",
    "https://www.horizon3.ai/feed/": "https://www.horizon3.ai/feed/",
    "https://www.mandiant.com/resources/blog/": "https://www.mandiant.com/resources/blog/rss.xml",
    "https://www.sentinelone.com/blog/": "https://www.sentinelone.com/blog/feed/",
}

def tag_visible(element):
    """Filter out invisible elements from HTML."""
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    try:
        if True in [value in ["related-articles"] for value in element.parent.attrs.values()]:
            return False
    except KeyError:
        pass
    return True

def is_recent_date(date_str, days_ago):
    """
    Improved date checking function that strictly checks if a date is within the specified timeframe.
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
    soup = BeautifulSoup(html_content, 'html.parser')
    texts = soup.findAll(string=True)  # Use string= instead of text= to avoid deprecation warning
    visible_texts = filter(tag_visible, texts)
    return ' '.join(t.strip() for t in visible_texts if t.strip())

def identify_vendors(text):
    """Identify mentioned vendors in the text."""
    found_vendors = []
    for vendor in TOP_VENDORS:
        pattern = r'\b' + re.escape(vendor) + r'\b'
        if re.search(pattern, text, re.IGNORECASE):
            found_vendors.append(vendor)
    return list(set(found_vendors))

def extract_impact(text, vendor_names):
    """Extract sentences mentioning impact and vulnerabilities."""
    impact_keywords = [
        "vulnerability", "exploit", "attack", "breach", "compromise", 
        "malware", "ransomware", "phishing", "data leak", "zero-day",
        "CVE", "patch", "security flaw", "backdoor", "threat", "risk",
        "critical", "high severity", "remote code execution", "RCE",
        "privilege escalation", "denial of service", "DoS", "data exposure"
    ]
    
    # Use our simple sentence tokenizer
    sentences = simple_sent_tokenize(text)
    impact_sentences = []
    
    for sentence in sentences:
        if any(vendor.lower() in sentence.lower() for vendor in vendor_names):
            if any(keyword.lower() in sentence.lower() for keyword in impact_keywords):
                impact_sentences.append(sentence)
    
    # Limit to 3 sentences at most
    summary = " ".join(impact_sentences[:3])
    if not summary:
        # If no specific impact sentences found, return general context
        for sentence in sentences:
            if any(keyword.lower() in sentence.lower() for keyword in impact_keywords):
                impact_sentences.append(sentence)
        summary = " ".join(impact_sentences[:3])
    
    return summary if summary else "Impact details not specified."

def create_incident_summary(title, link, vendors, impact, pub_date, source):
    """Create a structured summary of the incident."""
    return {
        "title": title,
        "link": link,
        "vendors": vendors,
        "impact": impact,
        "publication_date": pub_date,
        "source": source,
        "score": calculate_severity_score(impact) * len(vendors)  # Higher score for multiple vendors and severe impacts
    }

def calculate_severity_score(impact_text):
    """Calculate a severity score based on the impact description."""
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
        "patch": 2,
        "update": 1
    }
    
    score = 1  # Base score
    for term, value in severity_terms.items():
        if term.lower() in impact_text.lower():
            score += value
    
    return score

def get_cybersecurity_incidents_openai(api_key, top_vendors, days):
    """
    Fetch top cybersecurity incidents using OpenAI API.
    
    Args:
        api_key (str): OpenAI API key
        top_vendors (list): List of vendors to track
        days (int): Number of days to look back
        
    Returns:
        list: List of incident dictionaries
    """
    # Skip if no API key provided
    if not api_key or api_key == "your-openai-api-key-here":
        logger.warning("No valid OpenAI API key provided")
        return []
        
    # Format the vendors list for the prompt
    vendors_text = ", ".join(top_vendors[:20])  # Limit to 20 vendors to keep prompt size reasonable
    
    # Create the system prompt with emphasis on recency
    system_prompt = f"""You are a cybersecurity expert tasked with identifying important cybersecurity incidents 
    from the past {days} days. Focus on incidents involving these vendors: {vendors_text}.
    Pay special attention to vulnerabilities, exploits, attacks, breaches, malware, and ransomware.
    IMPORTANT: Only include incidents that have been published or reported in the last {days} days. Do not include older incidents.
    """
    
    # Create the user prompt
    user_prompt = f"""Search for cybersecurity incidents from sources like:
    - sans.org
    - cisa.gov
    - bleepingcomputer.com
    - thehackernews.com
    - krebsonsecurity.com
    - talosintelligence.com
    - trendmicro.com
    - unit42.paloaltonetworks.com

    For each incident, provide:
    1. A clear title describing the incident
    2. A list of affected vendors
    3. A 2-line summary of the impact
    4. The source URL
    5. The exact publication date in format "YYYY-MM-DD"
    
    Return exactly 5 incidents, prioritizing severity and recency. If fewer than 5 recent incidents exist within the past {days} days, return only those that are truly recent.
    Format as a JSON object with an "incidents" field containing an array of incidents, each with fields: title, vendors, impact, source, and date.
    """
    
    # Call OpenAI API
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "gpt-4o-mini",  # You can use gpt-3.5-turbo for lower cost
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
        incidents_data = json.loads(content)
        
        # Format the response to match your desired output format
        formatted_incidents = []
        
        # Check if the incidents data contains an 'incidents' field
        incidents = incidents_data.get('incidents', [])
        if not incidents and isinstance(incidents_data, list):
            # Handle case where API returns a direct array
            incidents = incidents_data
            
        logger.info(f"Received {len(incidents)} incidents from OpenAI API")
        
        for incident in incidents:
            # Extract vendors as a list if it's a string
            vendors = incident.get("vendors", [])
            if isinstance(vendors, str):
                vendors = [v.strip() for v in vendors.split(',')]
                
            # Use the date provided by the API, or today's date if not available
            pub_date = incident.get("date", datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0000"))
            
            formatted_incidents.append({
                "title": incident.get("title", ""),
                "vendors": vendors,
                "impact": incident.get("impact", ""),
                "publication_date": pub_date,
                "source": incident.get("source", "").split('/')[2] if '/' in incident.get("source", "") else incident.get("source", ""),
                "link": incident.get("source", ""),
                "score": calculate_severity_score(incident.get("impact", "")) * max(len(vendors), 1)
            })
        
        return formatted_incidents
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making request to OpenAI API: {e}")
        return []
    except (KeyError, json.JSONDecodeError) as e:
        logger.error(f"Error parsing response from OpenAI API: {e}")
        return []

class ReadRss:
    """Class for reading RSS feeds."""
    def __init__(self, rss_url, headers):
        self.url = rss_url
        self.headers = headers
        try:
            # Try to convert to RSS feed URL if available
            feed_url = RSS_FEED_MAPPINGS.get(rss_url, rss_url)
            self.r = requests.get(feed_url, headers=self.headers, timeout=30)
            self.status_code = self.r.status_code
        except Exception as e:
            print('Error fetching the URL: ', rss_url)
            print(e)
            raise
        try:    
            self.soup = BeautifulSoup(self.r.text, 'html.parser')
        except Exception as e:
            print('Could not parse the xml: ', self.url)
            print(e)
            raise
        
        # Handle cases where items might be differently structured
        self.articles = self.soup.findAll('item')
        
        # More robust extraction
        self.articles_dicts = []
        for a in self.articles:
            article_dict = {}
            
            # Title
            title_tag = a.find('title')
            if title_tag:
                article_dict['title'] = title_tag.text
            
            # Link - handle different link formats
            link_tag = a.find('link')
            if link_tag:
                if link_tag.next_sibling and isinstance(link_tag.next_sibling, str):
                    article_dict['link'] = link_tag.next_sibling.replace('\n','').replace('\t','')
                else:
                    article_dict['link'] = link_tag.text or link_tag.string or ""
            
            # Description
            desc_tag = a.find('description')
            if desc_tag:
                article_dict['description'] = desc_tag.text
            
            # Publication date - handle variations
            date_tag = a.find('pubdate') or a.find('pubDate')
            if date_tag:
                article_dict['pubdate'] = date_tag.text
            
            # Only add articles with required fields
            if 'title' in article_dict and 'link' in article_dict:
                self.articles_dicts.append(article_dict)
        
        # Extract lists for backwards compatibility
        self.urls = [d['link'] for d in self.articles_dicts if 'link' in d]
        self.titles = [d['title'] for d in self.articles_dicts if 'title' in d]
        self.descriptions = [d['description'] for d in self.articles_dicts if 'description' in d]
        self.pub_dates = [d['pubdate'] for d in self.articles_dicts if 'pubdate' in d]

def fetch_and_process_feeds(days_ago):
    """Fetch articles from RSS feeds and process them."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0'
    }
    
    incidents = []
    logger.info(f"Starting to fetch articles from the past {days_ago} day(s)")
    
    for feed_url in RSS_FEEDS:
        try:
            logger.info(f"Processing feed: {feed_url}")
            item = ReadRss(feed_url, headers)
            
            source_name = feed_url.split('/')[2]
            
            for article in item.articles_dicts:
                try:
                    title = article['title']
                    link = article['link']
                    
                    # Handle cases where pubdate might be missing
                    pub_date = article.get('pubdate', "Unknown date")
                    
                    # Check if article is recent using the improved date checker
                    if not is_recent_date(pub_date, days_ago):
                        logger.info(f"Skipping article, not recent enough: {title[:50]}... ({pub_date})")
                        continue
                    
                    # Safely log title with encoding handling
                    safe_title = title.encode('ascii', 'ignore').decode('ascii')
                    logger.info(f"Found recent article: {safe_title}")
                    
                    # Fetch the full article
                    article_response = requests.get(link.strip(), headers=headers, timeout=30)
                    article_text = extract_text_from_html(article_response.text)
                    
                    # Identify vendors
                    found_vendors = identify_vendors(title + " " + article_text)
                    
                    # Only process articles mentioning tracked vendors
                    if found_vendors:
                        logger.info(f"Article mentions vendors: {', '.join(found_vendors)}")
                        impact = extract_impact(article_text, found_vendors)
                        
                        incident = create_incident_summary(
                            title=title,
                            link=link,
                            vendors=found_vendors,
                            impact=impact,
                            pub_date=pub_date,
                            source=source_name
                        )
                        
                        incidents.append(incident)
                        logger.info(f"Added incident: {title[:50]}... (from {pub_date})")
                
                except Exception as e:
                    logger.error(f"Error processing article: {str(e)}")
                    continue
        
        except Exception as e:
            logger.error(f"Error processing feed {feed_url}: {str(e)}")
            continue
    
    logger.info(f"Found {len(incidents)} relevant incidents from RSS feeds")
    return incidents

def format_report(incidents):
    """Format incidents for a readable report."""
    if not incidents:
        return "No significant cybersecurity incidents found."
    
    message = "TOP CYBERSECURITY INCIDENTS\n\n"
    
    for i, incident in enumerate(incidents, 1):
        vendors_text = ", ".join(incident["vendors"])
        
        message += f"{i}. {incident['title']}\n"
        message += f"Source: {incident['source']}\n"
        message += f"Link: {incident['link']}\n"
        message += f"Publication Date: {incident['publication_date']}\n\n"
    
    message += "Security analysts should review these incidents before final publication to customers."
    return message

def save_incidents(incidents):
    """Save incidents to a JSON file."""
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(incidents, f, indent=2)
    logger.info(f"Saved incidents to {OUTPUT_FILE}")

def fetch_cybersecurity_incidents(days_ago):
    """Main function to fetch cybersecurity incidents."""
    logger.info("Starting cybersecurity incidents report")
    
    all_incidents = []
    
    # Try OpenAI API first
    if OPENAI_API_KEY and OPENAI_API_KEY != "your-openai-api-key-here":
        logger.info("Using OpenAI API to fetch incidents")
        try:
            openai_incidents = get_cybersecurity_incidents_openai(OPENAI_API_KEY, TOP_VENDORS, days_ago)
            all_incidents.extend(openai_incidents)
            logger.info(f"Found {len(openai_incidents)} incidents via OpenAI API")
        except Exception as e:
            logger.error(f"Error using OpenAI API: {str(e)}")
    else:
        logger.info("No OpenAI API key provided, skipping OpenAI API")
    
    # Always process RSS feeds as backup or supplement
    try:
        rss_incidents = fetch_and_process_feeds(days_ago)
        all_incidents.extend(rss_incidents)
        logger.info(f"Found {len(rss_incidents)} incidents from RSS feeds")
    except Exception as e:
        logger.error(f"Error processing RSS feeds: {str(e)}")
    
    # Filter out incidents that are older than the specified timeframe
    recent_incidents = []
    for incident in all_incidents:
        pub_date = incident.get("publication_date", "")
        if is_recent_date(pub_date, days_ago):
            recent_incidents.append(incident)
        else:
            logger.info(f"Filtering out old incident: {incident['title'][:50]}... ({pub_date})")
    
    logger.info(f"After date filtering: {len(recent_incidents)} recent incidents")
    
    # Sort by score and select top 5
    if recent_incidents:
        incidents = sorted(recent_incidents, key=lambda x: x["score"], reverse=True)[:5]
        save_incidents(incidents)
        logger.info("Cybersecurity incidents report completed")
        return incidents
    else:
        logger.warning("No recent incidents found")
        return []

#---------------------------
# Streamlit UI Functions
#---------------------------

def format_incident_card(incident, idx):
    """Format a single incident as an HTML card."""
    severity_class = "high-severity" if incident.get("score", 0) > 15 else "medium-severity" if incident.get("score", 0) > 8 else "low-severity"
    
    html = f"""
    <div class="incident-card {severity_class}">
        <div class="incident-header">{idx}. {incident['title']}</div>
        <div class="incident-meta">
            Source: {incident['source']} | Published: {incident.get('publication_date', 'N/A')}
        </div>
        <div style="margin-top: 15px;">
            <a href="{incident['link']}" target="_blank" class="incident-link">
                {incident['link']}
            </a>
        </div>
    </div>
    """
    return html

# Set up page configuration
st.set_page_config(
    page_title="Cybersecurity Incidents Monitor",
    page_icon="🔒",
    layout="wide",
)

# Custom CSS
st.markdown("""
<style>
    .main {
        padding: 1rem 1rem;
    }
    .reportview-container .main .block-container {
        padding: 1rem 1rem 1rem 1rem;
        max-width: 1000px;
    }
    .incident-card {
        background-color: #f8f9fa;
        border-radius: 5px;
        padding: 15px;
        margin-bottom: 20px;
        border-left: 5px solid #4CAF50;
    }
    .incident-header {
        font-weight: bold;
        font-size: 18px;
        margin-bottom: 10px;
    }
    .incident-meta {
        color: #666;
        font-size: 14px;
        margin-bottom: 10px;
    }
    .incident-link {
        color: #1e88e5;
        text-decoration: none;
        font-weight: bold;
        font-size: 14px;
        word-break: break-all;
    }
    .high-severity {
        border-left: 5px solid #f44336;
    }
    .medium-severity {
        border-left: 5px solid #ff9800;
    }
    .low-severity {
        border-left: 5px solid #4CAF50;
    }
    .days-slider {
        padding-top: 10px;
        padding-bottom: 30px;
    }
</style>
""", unsafe_allow_html=True)

# Main title
st.title("Cybersecurity Incidents Monitor")

# Set up session state to track if incidents have been fetched
if 'incidents_fetched' not in st.session_state:
    st.session_state.incidents_fetched = False
    st.session_state.incidents = []

# Days to look back - slider from 1 to 30
days_ago = st.slider("Number of days to look back:", min_value=1, max_value=30, value=2, key="days_slider", 
                    help="Select how many days in the past to search for incidents")

# OpenAI API Key input - for Streamlit Cloud, use st.secrets instead
api_key_placeholder = "Using API key from Streamlit secrets" if OPENAI_API_KEY else "No API key configured"
use_openai = st.checkbox("Use OpenAI API for enhanced results", value=bool(OPENAI_API_KEY), 
                        help="When enabled, uses OpenAI API to fetch additional cybersecurity incidents")

if not OPENAI_API_KEY and use_openai:
    st.warning("⚠️ OpenAI API key not configured in secrets. RSS feeds will be used instead.")

# Single button for fetching incidents
if st.button("FETCH CYBERSECURITY INCIDENTS", key="fetch_button", use_container_width=True):
    with st.spinner(f"Fetching cybersecurity incidents from the past {days_ago} days..."):
        incidents = fetch_cybersecurity_incidents(days_ago)
        if incidents:
            st.session_state.incidents = incidents
            st.session_state.incidents_fetched = True
            st.success(f"Found {len(incidents)} cybersecurity incidents from the past {days_ago} days")
        else:
            st.session_state.incidents = []
            st.session_state.incidents_fetched = True
            st.warning(f"No cybersecurity incidents found in the past {days_ago} days. Try extending the search period.")

# CSV Export Button - only show if incidents are available
if st.session_state.incidents_fetched and st.session_state.incidents:
    csv_data = pd.json_normalize(st.session_state.incidents).to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download as CSV",
        data=csv_data,
        file_name="cybersecurity_incidents.csv",
        mime="text/csv",
        key="download_csv",
        use_container_width=True
    )

# Display incidents
st.header("Detailed Incidents")

if st.session_state.incidents_fetched:
    if st.session_state.incidents:
        for i, incident in enumerate(st.session_state.incidents, 1):
            st.markdown(format_incident_card(incident, i), unsafe_allow_html=True)
            
            # Add expandable details section
            with st.expander(f"View Details - {incident['title'][:50]}..."):
                st.subheader("Affected Vendors")
                st.write(", ".join(incident["vendors"]))
                
                st.subheader("Impact")
                st.write(incident["impact"])
                
                st.subheader("Severity Score")
                severity = "High" if incident.get("score", 0) > 15 else "Medium" if incident.get("score", 0) > 8 else "Low"
                st.write(f"{severity} (Score: {incident.get('score', 0)})")
    else:
        st.info(f"No incidents found in the past {days_ago} days. Try adjusting the search period or click the 'FETCH CYBERSECURITY INCIDENTS' button again.")
else:
    st.info("Click the 'FETCH CYBERSECURITY INCIDENTS' button to get the latest cybersecurity information.")

# Display information about the app in the sidebar
with st.sidebar:
    st.title("About")
    st.markdown("""
    This app fetches and displays recent cybersecurity incidents affecting major vendors.
    
    **Features:**
    - Monitors 25+ cybersecurity news sources
    - Tracks incidents for 50+ major vendors
    - Calculates severity scores
    - Export data to CSV
    
    **How it works:**
    1. Set the number of days to look back
    2. Click "FETCH CYBERSECURITY INCIDENTS"
    3. View and analyze the results
    """)
    
    st.markdown("---")
    st.subheader("Sources")
    st.markdown("Data is collected from reputable cybersecurity sources including:")
    sources_list = ["SANS ISC", "CISA", "Bleeping Computer", "Krebs on Security", "Talos Intelligence", "The Hacker News"]
    for source in sources_list:
        st.markdown(f"- {source}")
