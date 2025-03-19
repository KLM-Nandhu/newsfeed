import streamlit as st
import pandas as pd
import requests
import datetime
import time
import json
import random
import os
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import threading
import hashlib

# API configuration - getting from environment variables for cloud security
PPLX_API_KEY = os.environ.get('PPLX_API_KEY', '')

# List of cybersecurity news sources to scrape
SOURCES = [
    {"url": "https://www.sans.org/newsletters/at-risk/", "priority": "high"},
    {"url": "https://isc.sans.edu/diaryarchive.html", "priority": "high"},
    {"url": "https://us-cert.cisa.gov/ncas", "priority": "high"},
    {"url": "https://isc.sans.edu/podcast.html", "priority": "high"},
    {"url": "https://www.bleepingcomputer.com/", "priority": "high"},
    {"url": "https://securelist.com/", "priority": "high"},
    {"url": "https://www.trendmicro.com/en_us/research.html", "priority": "high"},
    {"url": "https://blog.malwarebytes.com/", "priority": "high"},
    {"url": "https://cofense.com/blog/", "priority": "high"},
    {"url": "https://www.zdnet.com/", "priority": "medium"},
    {"url": "https://www.bitdefender.com/blog/", "priority": "medium"},
    {"url": "https://thehackernews.com/", "priority": "medium"},
    {"url": "https://krebsonsecurity.com/", "priority": "medium"},
    {"url": "https://gbhackers.com/", "priority": "medium"},
    {"url": "https://blog.talosintelligence.com/", "priority": "medium"},
    {"url": "https://www.crowdstrike.com/blog/", "priority": "medium"},
    {"url": "https://sysdig.com/blog/", "priority": "medium"},
    {"url": "https://research.checkpoint.com/latest-publications/", "priority": "medium"},
    {"url": "https://nakedsecurity.sophos.com/", "priority": "medium"},
    {"url": "https://unit42.paloaltonetworks.com/", "priority": "medium"},
    {"url": "https://www.horizon3.ai/feed/", "priority": "medium"},
    {"url": "https://www.mandiant.com/resources/blog/", "priority": "medium"},
    {"url": "https://www.sentinelone.com/blog/", "priority": "medium"},
    {"url": "https://aws.amazon.com/security/security-bulletins/", "priority": "medium"}
]

# Headers to mimic a browser request
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

def format_incident_card(incident, idx):
    """Format a single incident as an HTML card."""
    severity_class = "high-severity" if incident.get("severity_score", 0) > 80 else "medium-severity" if incident.get("severity_score", 0) > 50 else "low-severity"
    
    html = f"""
    <div class="incident-card {severity_class}">
        <div class="incident-header">{idx}. {incident['title']}</div>
        <div class="incident-meta">
            Source: {incident.get('source_name', 'Unknown Source')} | Published: {incident.get('date', 'N/A')}
        </div>
        <div style="margin-top: 15px;">
            <a href="{incident['link']}" target="_blank" class="incident-link">
                {incident['link']}
            </a>
        </div>
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
        time.sleep(random.uniform(1, 3))  # Random delay between 1-3 seconds
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        st.error(f"Error fetching {url}: {e}")
        return None

def extract_articles(html_content, source_url):
    articles = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for article tags, divs with article class, or common blog post structures
        potential_articles = (
            soup.find_all('article') or 
            soup.find_all('div', class_=['post', 'entry', 'blog-post', 'news-item']) or
            soup.select('.post, .article, .blog-item, .news-entry')
        )
        
        # If no structure found, look for headings with links
        if not potential_articles:
            potential_articles = soup.select('h1 a, h2 a, h3 a')
            
        for article in potential_articles[:10]:  # Limit to 10 articles per source
            title_elem = article.find('h1') or article.find('h2') or article.find('h3') or article.find('a')
            
            if title_elem:
                title = title_elem.text.strip()
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
                
                # Try to find date
                date_elem = article.find('time') or article.select_one('.date, .meta-date, .published, .post-date')
                date = date_elem.text.strip() if date_elem else "Unknown date"
                
                # Try to find description/summary
                desc_elem = article.find('p') or article.select_one('.excerpt, .summary, .description')
                description = desc_elem.text.strip() if desc_elem else ""
                
                if title and link:
                    articles.append({
                        "title": title,
                        "link": link,
                        "date": date,
                        "description": description[:200] + "..." if len(description) > 200 else description,
                        "source": source_url,
                        "source_name": source_url.split('//')[-1].split('/')[0].replace('www.', '')
                    })
        
    except Exception as e:
        st.error(f"Error extracting articles from {source_url}: {e}")
    
    return articles

def query_perplexity_api(query):
    url = "https://api.perplexity.ai/chat/completions"
    
    # Skip API call if no API key is provided
    if not PPLX_API_KEY:
        return None
    
    payload = {
        "model": "sonar",
        "messages": [
            {
                "role": "system",
                "content": """You are a cybersecurity expert specializing in finding the latest cybersecurity incidents, 
                attacks, vulnerabilities, updates, and important security news. Focus on professional, 
                actionable intelligence and filter out generic weekly summaries or non-specific content. 
                Include detailed information about incidents, CVEs, patches, product releases, and security measures 
                when available. Return your analysis in JSON format with the following structure:
                {
                    "type": "vulnerability|attack|patch|product_release|security_measure",
                    "severity": "low|medium|high|critical",
                    "affected_vendors": ["vendor1", "vendor2"],
                    "cve_ids": ["CVE-XXXX-XXXX"],
                    "impact": "Description of the impact",
                    "iocs": ["indicator1", "indicator2"],
                    "mitigation": "Steps to mitigate the issue"
                }
                """
            },
            {
                "role": "user",
                "content": query
            }
        ],
        "max_tokens": 1000
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {PPLX_API_KEY}"
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Error querying Perplexity API: {e}")
        return None

def process_source(source, days_to_look_back):
    source_url = source["url"]
    priority = source["priority"]
    
    # For SANS ISC diary archive, modify URL to include year and month
    if "isc.sans.edu/diaryarchive.html" in source_url and not "year=" in source_url:
        current_date = datetime.datetime.now()
        current_year = current_date.year
        current_month = current_date.month
        source_url = f"https://isc.sans.edu/diaryarchive.html?year={current_year}&month={current_month}"
    
    html_content = make_request(source_url)
    
    if not html_content:
        return []
    
    articles = extract_articles(html_content, source_url)
    
    # Filter articles based on date if possible
    filtered_articles = []
    cutoff_date = get_date_n_days_back(days_to_look_back)
    
    for article in articles:
        # Try to parse the date - this is tricky as date formats vary widely
        try:
            # This is a simple approach - in a production system you'd want more robust date parsing
            if "unknown" not in article["date"].lower():
                article_date = article["date"]
                # Keep the article if we can't determine its date or if it's after our cutoff
                filtered_articles.append(article)
        except:
            # If date parsing fails, include the article anyway
            filtered_articles.append(article)
    
    return filtered_articles

def enhance_article_data(article):
    query = f"Analyze this cybersecurity news: {article['title']}. If available from the title or description, extract: incident type, affected vendors, CVE numbers, severity, impact, and mitigation steps."
    
    enhanced_data = query_perplexity_api(query)
    
    if enhanced_data and "choices" in enhanced_data and enhanced_data["choices"]:
        try:
            content = enhanced_data["choices"][0]["message"]["content"]
            # Try to parse as JSON
            try:
                structured_data = json.loads(content)
                article.update({
                    "type": structured_data.get("type", "unknown"),
                    "severity": structured_data.get("severity", "medium"),
                    "affected_vendors": structured_data.get("affected_vendors", []),
                    "cve_ids": structured_data.get("cve_ids", []),
                    "impact": structured_data.get("impact", ""),
                    "iocs": structured_data.get("iocs", []),
                    "mitigation": structured_data.get("mitigation", "")
                })
                
                # Calculate severity score (0-100)
                severity_map = {
                    "low": 30,
                    "medium": 50,
                    "high": 80,
                    "critical": 95
                }
                article["severity_score"] = severity_map.get(structured_data.get("severity", "medium"), 50)
                
            except json.JSONDecodeError:
                # If not valid JSON, try to extract key information using keywords
                article["type"] = "unknown"
                article["severity"] = "medium"
                article["severity_score"] = 50
                
                # Check for vendors
                vendors = []
                common_vendors = ["Microsoft", "Cisco", "Oracle", "Google", "Apple", "Amazon", "IBM", 
                                 "Adobe", "VMware", "SAP", "Fortinet", "Palo Alto", "Juniper", "F5", 
                                 "Citrix", "Red Hat", "Ubuntu", "Linux", "Android", "Windows"]
                for vendor in common_vendors:
                    if vendor.lower() in content.lower():
                        vendors.append(vendor)
                article["affected_vendors"] = vendors
                
                # Check for CVEs
                cves = re.findall(r'CVE-\d{4}-\d{4,7}', content)
                article["cve_ids"] = cves
                
                # Extract possible impact
                impact_sentences = re.findall(r'([^.]*impact[^.]*\.)', content, re.IGNORECASE)
                article["impact"] = ' '.join(impact_sentences) if impact_sentences else ""
                
        except Exception as e:
            st.error(f"Error processing enhanced data for article '{article['title']}': {e}")
    
    # Generate a unique ID for the incident
    article["id"] = hashlib.md5(f"{article['title']}:{article['link']}".encode()).hexdigest()
    
    # If vendors weren't found previously, try to extract from title/description
    if not article.get("affected_vendors"):
        article["affected_vendors"] = extract_vendors_from_text(f"{article['title']} {article.get('description', '')}")
    
    # For compatibility with provided template
    article["vendors"] = article.get("affected_vendors", [])
    article["score"] = article.get("severity_score", 0)
    if not article.get("impact"):
        article["impact"] = "No specific impact information available"
    
    return article

def extract_vendors_from_text(text):
    common_vendors = ["Microsoft", "Cisco", "Oracle", "Google", "Apple", "Amazon", "IBM", 
                     "Adobe", "VMware", "SAP", "Fortinet", "Palo Alto", "Juniper", "F5", 
                     "Citrix", "Red Hat", "Ubuntu", "Linux", "Android", "Windows", "CrowdStrike",
                     "Kaspersky", "Symantec", "McAfee", "ESET", "Trend Micro", "SentinelOne",
                     "Sophos", "CheckPoint", "Bitdefender", "Avast", "AVG", "Norton", "Malwarebytes"]
    
    found_vendors = []
    for vendor in common_vendors:
        if vendor.lower() in text.lower():
            found_vendors.append(vendor)
    
    return found_vendors

def fetch_cybersecurity_incidents(days_to_look_back=7, use_api=True, min_entries=5):
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        status_text.text(f"Fetching cybersecurity incidents from the past {days_to_look_back} days...")
        
        all_articles = []
        
        # Process high priority sources first
        high_priority_sources = [s for s in SOURCES if s["priority"] == "high"]
        medium_priority_sources = [s for s in SOURCES if s["priority"] == "medium"]
        
        total_sources = len(high_priority_sources) + len(medium_priority_sources)
        processed_sources = 0
        
        # Process high priority sources
        for source in high_priority_sources:
            status_text.text(f"Fetching from {source['url']}...")
            articles = process_source(source, days_to_look_back)
            all_articles.extend(articles)
            processed_sources += 1
            progress_bar.progress(processed_sources / total_sources)
        
        # If we don't have enough articles, process medium priority sources too
        if len(all_articles) < min_entries * 2:  # Get more than we need for filtering
            for source in medium_priority_sources:
                status_text.text(f"Fetching from {source['url']}...")
                articles = process_source(source, days_to_look_back)
                all_articles.extend(articles)
                processed_sources += 1
                progress_bar.progress(processed_sources / total_sources)
        
        # Remove duplicates (based on title similarity)
        unique_articles = []
        seen_titles = set()
        
        for article in all_articles:
            title_normalized = article["title"].lower()
            # Check if we've seen a very similar title
            if not any(title_normalized in seen_title or seen_title in title_normalized for seen_title in seen_titles):
                seen_titles.add(title_normalized)
                unique_articles.append(article)
        
        status_text.text(f"Found {len(unique_articles)} unique articles")
        
        # If using API, enhance top articles with Perplexity API
        enhanced_articles = []
        
        if use_api and PPLX_API_KEY:
            # Sort by priority and limit to manage API usage
            articles_to_enhance = unique_articles[:min(15, len(unique_articles))]
            
            status_text.text(f"Enhancing {len(articles_to_enhance)} articles with Perplexity API...")
            
            for i, article in enumerate(articles_to_enhance):
                status_text.text(f"Enhancing article {i+1} of {len(articles_to_enhance)}...")
                enhanced_article = enhance_article_data(article)
                enhanced_articles.append(enhanced_article)
                progress_bar.progress((processed_sources + i/len(articles_to_enhance)) / (total_sources + 1))
        elif use_api and not PPLX_API_KEY:
            st.warning("Perplexity API key not provided. Using basic article extraction without enhancement.")
        
        # If we didn't enhance any articles, use the original ones
        final_articles = enhanced_articles if enhanced_articles else unique_articles
        
        # Ensure we have at least min_entries entries
        if len(final_articles) < min_entries:
            status_text.text(f"Warning: Only found {len(final_articles)} entries, which is less than the requested minimum of {min_entries}")
        
        # Sort by severity score (if available) or just by recency
        final_articles.sort(key=lambda x: x.get("severity_score", 0), reverse=True)
        
        progress_bar.progress(1.0)
        status_text.empty()
        
        return final_articles
    
    except Exception as e:
        st.error(f"Error fetching incidents: {e}")
        return []
    
    finally:
        progress_bar.empty()
        status_text.empty()

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

# Perplexity API option
use_perplexity = st.checkbox("Use Perplexity API for enhanced results", value=bool(PPLX_API_KEY), 
                           help="When enabled, uses Perplexity API to fetch additional cybersecurity incident details")

if not PPLX_API_KEY and use_perplexity:
    st.warning("⚠️ Perplexity API key not configured. Set the PPLX_API_KEY environment variable for enhanced results.")

# Single button for fetching incidents
if st.button("FETCH CYBERSECURITY INCIDENTS", key="fetch_button", use_container_width=True):
    with st.spinner(f"Fetching cybersecurity incidents from the past {days_ago} days..."):
        incidents = fetch_cybersecurity_incidents(days_ago, use_perplexity)
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
                if incident.get("vendors") and len(incident["vendors"]) > 0:
                    st.write(", ".join(incident["vendors"]))
                else:
                    st.write("No specific vendors identified")
                
                st.subheader("Impact")
                st.write(incident.get("impact", "No impact information available"))
                
                if incident.get("cve_ids") and len(incident["cve_ids"]) > 0:
                    st.subheader("CVE IDs")
                    st.write(", ".join(incident["cve_ids"]))
                
                if incident.get("mitigation"):
                    st.subheader("Mitigation")
                    st.write(incident["mitigation"])
                
                st.subheader("Severity Score")
                severity = "High" if incident.get("score", 0) > 70 else "Medium" if incident.get("score", 0) > 40 else "Low"
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

    # Add contact information for cloud deployment
    st.markdown("---")
    st.subheader("Contact")
    st.markdown("For questions or support, please contact: support@example.com")
