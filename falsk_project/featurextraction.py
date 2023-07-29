# Importing required packages for this section
import urllib
from urllib.parse import urlparse, urlencode
import ipaddress
import re
import requests
import numpy as np
import whois
import datetime
from bs4 import BeautifulSoup
import os
import networkx as nx

# f1. IP Address in the URL
# Checks for the presence of an IP address in the URL.
# If an IP address is used instead of a domain name, it might indicate phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = -1  # phishing
    except:
        ip = 1  # legitimate
    return ip

# f2. Length of URL
# Computes the length of the URL.
# Phishers can use long URLs to hide the doubtful part in the address bar.
# If the length of URL is greater than or equal to 54 characters, the URL is classified as phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and 0 for potential phishing.
def getLength(url):
    if len(url) < 54:
        length = 1  # legitimate
    else:
        length = 0  # phishing
    return length

# f3. Using URL Shortening Services "TinyURL"
# URL shortening is a method on the World Wide Web in which a URL may be made considerably smaller in length and still lead to the required webpage.
# If the URL is using shortening services, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def tinyURL(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

    match = re.search(shortening_services, url)
    if match:
        return -1  # phishing
    else:
        return 1  # legitimate

# f4. Presence of "@" Symbol in URL
# Checks for the presence of '@' symbol in the URL.
# Using "@" symbol in the URL leads the browser to ignore everything preceding the "@" symbol, and the real address often follows the "@" symbol.
# If the URL has '@' symbol, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def haveAtSign(url):
    if "@" in url:
        at = -1  # phishing
    else:
        at = 1  # legitimate
    return at

# f5. Double Slash Redirection
# Checks the presence of "//" in the URL.
# The existence of "//" within the URL path means that the user will be redirected to another website.
# If the "//" is anywhere in the URL apart from after the protocol, the URL is classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and 0 for potential phishing.
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return -1  # phishing
        else:
            return 1  # legitimate
    else:
        return 1  # legitimate

# f6. Prefix or Suffix "-" in Domain
# Checks the presence of '-' in the domain part of the URL.
# The dash symbol is rarely used in legitimate URLs.
# If the URL has '-' symbol in the domain part, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return -1  # phishing
    else:
        return 1  # legitimate

# f7. Presence of Subdomain
# Checks if the URL has a subdomain.
# Phishing websites may have multiple subdomains to imitate legitimate websites.
# If the URL has no more than two subdomains, it's classified as legitimate; otherwise, it's potential phishing.
# Returns 1 for legitimate URL and 0 for potential phishing.
def detect_subdomain(url):
    domain = urlparse(url).netloc
    subdomain = domain.split(".")
    return int(len(subdomain) <= 2)

# f8. "http/https" in Domain Name
# Checks for the presence of "http/https" in the domain part of the URL.
# Phishers may add the "HTTPS" token to the domain part of a URL to trick users.
# If the URL has "http/https" in the domain part, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def detect_ssl_final_state(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            if response.url.startswith('https'):
                return 1  # SSL certificate is valid (secure connection)
            else:
                return 0  # Non-SSL connection
        else:
            return -1  # URL not reachable or other error
    except requests.exceptions.RequestException:
        return -1  # URL not reachable or other error

# f9. Domain Registration Length
# Checks the age of the domain based on its registration date.
# If the age of the domain is greater than or equal to 6 months, it's classified as legitimate; otherwise, it's potential phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def is_phishing_url(url):
    domain = urlparse(url).netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is not None:
            current_date = datetime.datetime.now()
            registration_length = (current_date - creation_date).days // 30  # In months

            if registration_length >= 6:
                return 1
            else:
                return -1
        else:
            return -1
    except Exception as e:
        return -1

# f10. Favicon
# Checks if the URL has a favicon (icon displayed in the browser's address bar or tab).
# If a favicon is found, it's classified as legitimate; otherwise, it's potential phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def hasFavicon(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            if 'favicon' in response.text.lower():
                return 1  # Legitimate URL
        return -1  # Suspicious URL
    except requests.exceptions.RequestException:
        # Unable to make a request to the URL
        return -1  # Assume it's suspicious if the request fails

# f11. Port
# Checks if the URL has a specific port number in its domain part.
# If a port number is found, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_port(url):
    parsed_url = urlparse(url)
    return 1 if parsed_url.port else -1

# f12. HTTPS Token
# Checks if the URL has "https" in its domain part.
# If "https" is found, it's classified as legitimate; otherwise, it's potential phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_https_token(url):
    parsed_url = urlparse(url)
    return 1 if "https" in parsed_url.netloc else -1

# f13. Request URL
# Checks if the URL has a request (query) part.
# If a request URL is found, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_request_url(url):
    parsed_url = urlparse(url)
    return -1 if parsed_url.query else 1

# f14. URL of Anchor
# Checks if the URL contains anchors (hyperlinks).
# If anchors are found, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_url_of_anchor(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        soup = BeautifulSoup(response.content, 'html.parser')
        anchor_tags = soup.find_all('a')
        return 0 if anchor_tags else 1
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL

# f15. Links in Tags
# Checks if the URL has links to other domains in its HTML tags.
# If links to other domains are found, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_domain_links_in_tags(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        soup = BeautifulSoup(response.content, 'html.parser')
        anchor_tags = soup.find_all('a', href=True)

        original_domain = urlparse(url).netloc
        for tag in anchor_tags:
            link = tag['href']
            parsed_link = urlparse(link)
            if parsed_link.netloc != "" and parsed_link.netloc != original_domain:
                return 0  # Found a domain link in tags
        return 1  # No domain link in tags
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL

# f16. SFH - Server Form Handler
# Checks if the URL contains an empty form action or "about:blank".
# Empty form actions or "about:blank" can lead to phishing attacks.
# If an empty form action or "about:blank" is found, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_server_form_handler(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            if 'action' not in form.attrs or not form['action'] or form['action'].lower() == "about:blank":
                return 0  # Found a suspicious form handler
        return 1  # No suspicious form handler found
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL

# f17. Submitting Information to Email
# Checks if the URL submits form data to an email address.
# Phishers may use this technique to collect sensitive information via email.
# If the URL submits form data to an email address, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def submits_to_email(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            if 'mailto:' in form.get('action', ''):
                return 0  # Found a form submitting to an email address
        return 1  # No form submitting to an email address found
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL

# f18. Abnormal URL
# Checks for the presence of suspicious keywords in the URL.
# If any suspicious keyword is found, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_abnormal_url(url):
    suspicious_keywords = [
        "confirm", "account", "secure", "login", "submit", "password", "admin", "verification", "ebayisapi", "signin",
        "banking", "update", "customer", "signin", "webscr", "paypal", "login", "signin", "amazon", "accounts"
    ]
    for keyword in suspicious_keywords:
        if keyword in url:
            return 0  # Found a suspicious keyword in the URL
    return 1  # No suspicious keyword found, it's legitimate

# f19. Website Forwarding
# Checks if the URL redirects to another website.
# Phishers often use forwarding techniques to redirect users to malicious sites.
# If the URL redirects, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_website_forwarding(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if 300 <= response.status_code < 400:
            return 0  # Found website forwarding
        return 1  # No website forwarding found, it's legitimate
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL

# f20. Status Bar Customization
# Checks if the URL modifies the status bar (e.g., JavaScript-based status bar updates).
# Phishers may use this technique to display misleading information in the status bar.
# If the URL modifies the status bar, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
"""
def modifies_status_bar(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        if 'window.status' in response.text:
            return 0  # Found status bar customization
        return 1  # No status bar customization found, it's legitimate
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL
"""
def mouseOver(url): 
  try:
    response = requests.get(url)
  except:
    response = ""
  if response == "" :
    return -1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return -1
    else:
       return 1

# f21. Disabling Right-Click
# Checks if the URL disables the right-click functionality on the page.
# Phishers may use this technique to prevent users from accessing the browser's context menu.
# If the right-click functionality is disabled, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
"""
def disables_right_click(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        if 'event.button==2' in response.text or 'event.button == 2' in response.text:
            return 0  # Right-click functionality is disabled
        return 1  # Right-click functionality is not disabled, it's legitimate
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL
"""
def rightClick(url):
  try:
    response = requests.get(url)
  except:
    response = ""
  if response == "":
    return -1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 1
    else:
      return -1

# f22. Using Pop-up Windows
# Checks if the URL uses pop-up windows.
# Phishers may use pop-ups to display misleading information or collect sensitive data.
# If the URL uses pop-up windows, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
"""
def uses_popups(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        if 'pop-up' in response.text.lower() or 'popup' in response.text.lower():
            return 0  # Found usage of pop-up windows
        return 1  # No usage of pop-up windows found, it's legitimate
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL
"""
def has_popup_window(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check for JavaScript functions that open new windows
        javascript_functions = ['window.open', 'window.showModalDialog']
        for script_tag in soup.find_all('script'):
            script_content = script_tag.string
            if script_content:
                for function in javascript_functions:
                    if function in script_content:
                        return -1  # Popup window detected

        return 1  # No popup window detected
    except:
        return -1  # Error occurred

# f23. Iframe Redirection
# Checks if the URL uses iframes (inline frames) for redirection.
# Phishers may use iframes to redirect users to malicious websites without their knowledge.
# If the URL uses iframes for redirection, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def uses_iframe_redirection(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for successful response
        if '<iframe' in response.text:
            return 0  # Found usage of iframe for redirection
        return 1  # No usage of iframe for redirection found, it's legitimate
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL

# f24. Age of Domain
# Checks the age of the domain based on its creation date.
# If the age of the domain is less than one year, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def is_new_domain(url):
    domain = urlparse(url).netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is not None:
            current_date = datetime.datetime.now()
            age_of_domain = (current_date - creation_date).days // 365  # In years

            if age_of_domain < 1:
                return -1  # Potential phishing as it's a new domain
            else:
                return 1  # Domain age is more than one year, it's legitimate
        else:
            return -1  # Unable to determine domain age, assume it's a new domain
    except Exception as e:
        return -1  # Error occurred while fetching domain information, assume it's a new domain

# f25. DNS Record
# Checks if the URL has a valid DNS record.
# Phishers may use unregistered domains or misspelled domains that do not have a valid DNS record.
# If the URL has a valid DNS record, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_dns_record(url):
    domain = urlparse(url).netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    try:
        ipaddress.ip_address(domain)  # If this succeeds, it means the domain has a valid DNS record
        return 1  # Valid DNS record found, it's legitimate
    except:
        return -1  # No valid DNS record found, it's potential phishing

# f26. Web Traffic
# Measures the popularity of the website based on Alexa Rank.
# Phishing websites may not have significant traffic or may not be recognized by Alexa.
# If the website's Alexa Rank is below 100,000, it's classified as potential phishing; otherwise, it's legitimate.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + url).content, "xml").find(
            "REACH")['RANK']
        rank = int(rank)
    except (TypeError, requests.exceptions.RequestException):
        return -1
    if rank < 100000:
        return -1  # Potential phishing as it has low web traffic (Alexa Rank < 100,000)
    else:
        return 1  # Web traffic is significant, it's legitimate

# f27. Page Rank
# Measures the importance of the URL based on Google PageRank.
# Phishing websites may not have a high PageRank or may not be recognized by Google.
# If the URL has a high PageRank (above a threshold), it's classified as legitimate; otherwise, it's potential phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_high_page_rank(url, threshold=0.5):
    try:
        page_rank = nx.pagerank(nx.DiGraph(url), max_iter=30)[url]
        if page_rank is not None and page_rank >= threshold:
            return 1  # High PageRank, it's legitimate
        else:
            return -1  # Low PageRank, it's potential phishing
    except:
        return -1  # Unable to fetch PageRank, assume it's potential phishing

# f28. Google Indexed
# Checks if the URL is indexed by Google.
# Phishing websites may not be indexed by Google or may be blacklisted.
# If the URL is indexed by Google, it's classified as legitimate; otherwise, it's potential phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def is_indexed_by_google(url):
    # Replace 'YOUR_GOOGLE_SEARCH_CONSOLE_API_KEY_HERE' with your actual Google Search Console API key
    base_url = 'https://www.googleapis.com/webmasters/v3/sites/'
    search_url = f"{base_url}{url}/searchAnalytics/query"
    headers = {'Authorization': 'YOUR_GOOGLE_SEARCH_CONSOLE_API_KEY_HERE'}
    params = {
        'startDate': '2023-01-01',
        'endDate': '2023-05-01',
        'dimensions': ['page'],
        'query': f'page:{url}'
    }
    try:
        response = requests.post(search_url, headers=headers, json=params)
        response_json = response.json()

        if 'rows' in response_json:
            return 1  # URL is indexed by Google, it's legitimate
        else:
            return -1  # URL is not indexed by Google, it's potential phishing
    except requests.exceptions.RequestException:
        return -1  # Error occurred while fetching the URL, assume it's potential phishing

# f29. Links Pointing to a Page
# Checks if there are any links pointing to the URL.
# Phishing websites may not have many incoming links from other legitimate websites.
# If there are links pointing to the URL, it's classified as legitimate; otherwise, it's potential phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def has_links_pointing_to_page(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Error: Unable to fetch the page {url}")
            return None

        soup = BeautifulSoup(response.content, 'html.parser')
        anchor_tags = soup.find_all('a', href=True)

        for anchor in anchor_tags:
            href = anchor['href']
            if href.startswith(url):
                return 1  # Found links pointing to the URL, it's legitimate

        return -1  # No links pointing to the URL, it's potential phishing
    except Exception:
        return -1  # Error occurred while fetching the URL, assume it's potential phishing

# f30. Statistical Report
# Checks if the URL is associated with a statistical report.
# Phishing websites typically do not have statistical reports.
# If the URL is associated with a statistical report (based on the file extension), it's classified as legitimate;
# otherwise, it's potential phishing.
# Returns 1 for legitimate URL and -1 for potential phishing.
def is_statistical_report(url):
    # Extract the file extension from the URL
    _, file_extension = os.path.splitext(url)

    # List of common statistical report file extensions
    statistical_report_extensions = ['.pdf', '.xls', '.xlsx', '.csv', '.json']

    if file_extension.lower() in statistical_report_extensions:
        return 1  # URL is associated with a statistical report, it's legitimate
    else:
        return -1  # URL is not associated with a statistical report, it's potential phishing

        
"""
#f31.Result
import requests

def detect_url_result(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return 1  # URL returns a result
        else:
            return -1  # URL does not return a result
    except requests.exceptions.RequestException:
        return -1  # URL is not accessible or encountered an error
"""

def main(url):
   f=[]
   f.append(havingIP(url))
   f.append(getLength(url))
   f.append(tinyURL(url))
   f.append(haveAtSign(url))
   f.append(redirection(url))
   f.append(prefixSuffix(url))
   f.append(detect_subdomain(url))
   f.append(detect_ssl_final_state(url))
   f.append(is_phishing_url(url))
   f.append(hasFavicon(url))
   f.append(has_port(url))
   f.append(has_https_token(url))
   f.append(has_request_url(url))
   f.append(has_url_of_anchor(url))
   f.append(has_domain_links_in_tags(url))
   f.append(has_server_form_handler(url))
   f.append(submits_to_email(url))
   f.append(has_abnormal_url(url))
   f.append(has_website_forwarding(url))
   f.append(mouseOver(url))
   f.append(rightClick(url))
   f.append(has_popup_window(url))
   f.append(uses_iframe_redirection(url))
   f.append(is_new_domain(url))
   f.append(has_dns_record(url))
   f.append(has_web_traffic(url))
   f.append(has_high_page_rank(url))
   f.append(is_indexed_by_google(url))
   f.append(has_links_pointing_to_page(url))
   f.append(is_statistical_report(url))
   
   data_array = np.array(f).reshape(1, -1)
   return data_array