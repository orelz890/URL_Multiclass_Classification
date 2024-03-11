
import pandas as pd
import numpy as np
import re
import tldextract
from collections import Counter
import string
import ipaddress
from fuzzywuzzy import fuzz
from scipy.sparse import hstack
import joblib
from urllib.parse import urlparse
import pickle


class URLClassifier:
    def __init__(self,model, vectorizer, scaler, label_encoder):
        self.model = model
        self.vectorizer = vectorizer
        self.scaler = scaler
        self.label_encoder = label_encoder
        
        # Load all necessary models and transformers here
        # self.scaler = joblib.load('/app/scaler.joblib')
        # self.label_encoder = joblib.load('/app/label_encoder.joblib')
        # self.vectorizer = joblib.load('/app/tfidf_vectorizer.joblib')
        # self.model = joblib.load('/app/random_forest_model.joblib')
        # self.well_known_domains_df = pd.read_csv('/app/well_known_domains.csv')
        
        # Reference distribution for KL divergence
        all_chars = ''.join(filter(lambda x: x in string.printable and x != ' ', string.printable))
        self.reference_distribution = {char: 1/len(all_chars) for char in all_chars}
        
        # Define a regular expression pattern for characters you consider safe
        # This example allows alphanumeric characters, some special characters, and Unicode characters in the specified range
        # safe_pattern = re.compile(r'^[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$')

        # # Filter the DataFrame to keep only rows with URLs matching the pattern
        # # Note: Adjust the pattern as needed based on the characters you want to include
        # url_df = url_df[url_df['url'].apply(lambda x: bool(safe_pattern.match(x)) if pd.notnull(x) else False)]


    # Define your function to extract URL components
    def extract_url_components(self,url):
        try:
            if not urlparse(url).scheme and not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            extracted = tldextract.extract(url)
            full_domain = f"{extracted.subdomain + '.' if extracted.subdomain else ''}{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else "no_domain"
            parsed_url = urlparse(url)
            path = parsed_url.path if parsed_url.path else "/"
            query = parsed_url.query if parsed_url.query else "no_query"
            return full_domain, path, query
        except Exception as e:
            print(f"Error parsing URL {url}: {e}")
            return "no_domain", "/", "no_query"


    def character_distribution(self,text):
        if not text:
            return {}
        # Consider all printable characters, removing spaces
        text_cleaned = ''.join(filter(lambda x: x in string.printable and x != ' ', text))
        counter = Counter(text_cleaned)
        total = sum(counter.values())
        distribution = {char: count / total for char, count in counter.items()}
        return distribution


    def kl_divergence(self,p, q):
        epsilon = 1e-10
        divergence = sum(p[char] * np.log2(p[char] / (q.get(char, epsilon))) for char in p)
        return divergence




    def calculate_url_kl_divergence(self, url):
        # Example: Uniform distribution across all printable characters, excluding spaces
        all_chars = ''.join(filter(lambda x: x in string.printable and x != ' ', string.printable))
        reference_distribution = {char: 1/len(all_chars) for char in all_chars}
        url_distribution = self.character_distribution(url)
        return self.kl_divergence(url_distribution, reference_distribution)

    def calculate_domain_kl_divergence(self, url):
        # Example: Uniform distribution across all printable characters, excluding spaces
        all_chars = ''.join(filter(lambda x: x in string.printable and x != ' ', string.printable))
        reference_distribution = {char: 1/len(all_chars) for char in all_chars}
        domain = tldextract.extract(url).registered_domain
        domain_distribution = self.character_distribution(domain)
        return self.kl_divergence(domain_distribution, reference_distribution)

    def calculate_path_kl_divergence(self, url):
        # Example: Uniform distribution across all printable characters, excluding spaces
        all_chars = ''.join(filter(lambda x: x in string.printable and x != ' ', string.printable))
        reference_distribution = {char: 1/len(all_chars) for char in all_chars}
        path = urlparse(url).path
        path_distribution = self.character_distribution(path)
        return self.kl_divergence(path_distribution, reference_distribution)

    def calculate_query_kl_divergence(self, url):
        # Example: Uniform distribution across all printable characters, excluding spaces
        all_chars = ''.join(filter(lambda x: x in string.printable and x != ' ', string.printable))
        reference_distribution = {char: 1/len(all_chars) for char in all_chars}
        query = urlparse(url).query
        query_distribution = self.character_distribution(query)
        return self.kl_divergence(query_distribution, reference_distribution)

    def calculate_query_path_kl_divergence(self, url):
        # Example: Uniform distribution across all printable characters, excluding spaces
        all_chars = ''.join(filter(lambda x: x in string.printable and x != ' ', string.printable))
        reference_distribution = {char: 1/len(all_chars) for char in all_chars}
        path = urlparse(url).path
        query = urlparse(url).query
        path_distribution = self.character_distribution(path)
        query_distribution = self.character_distribution(query)
        return self.kl_divergence(path_distribution, query_distribution)

    # Number of special symbols
    def count_special_symbols(self,code):
        special_symbols = set('@#$%^&*()_-+={}[]|\:;"<>,.?/~`')
        return sum(1 for char in code if char in special_symbols)


    # Function to check for IP address presence
    def contains_ip_address(self,url):
        try:
            ipaddress.ip_address(urlparse(url).hostname)
            return 1
        except ValueError:
            return 0

    # Function to preprocess and tokenize URLs
    def tokenize_url(self,url):
        tokens = []
        url_parts = urlparse(url)

        # Tokenize domain
        domain_tokens = url_parts.netloc.split('.')
        tokens.extend(domain_tokens)

        # Tokenize path
        path_tokens = re.split('/|-|_', url_parts.path)
        tokens.extend(filter(None, path_tokens))  # filter removes empty strings

        # Tokenize query parameters
        query_tokens = re.split('=|&', url_parts.query)
        tokens.extend(filter(None, query_tokens))

        return ' '.join(tokens)


    def check_file_extensions(self,url):
        suspicious_file_extensions = [
            "exe", "scr", "vbs", "js", "xml", "docm", "xps", "iso", "img", "doc",
            "rtf", "xls", "pdf", "pub", "arj", "lzh", "r01", "r14", "r18", "r25",
            "tar", "ace", "zip", "jar", "bat", "cmd", "moz", "vb", "vbs", "js",
            "wsc", "wsh", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2"
        ]

        # Extract the file extension from the URL
        match = re.search(r'\.([a-zA-Z0-9]+)$', url)
        if match:
            extension = match.group(1).lower()
            if extension in suspicious_file_extensions:
                return 1
        return 0


    # Function to calculate the frequency of digits
    def digit_frequency(self,url):
        if not url:
            return 0
        digits = sum(c.isdigit() for c in url)
        return digits / len(url)

    def count_subdomains(self,url):
        subdomain = tldextract.extract(url).subdomain
        if subdomain:
            return subdomain.count('.') + 1  # Adding 1 because subdomains are separated by dots
        return 0


    # Function to count top-level domains
    def count_tlds(self,url):
        if len(tldextract.extract(url).suffix.split(".")):
            return len(tldextract.extract(url).suffix.split("."))
        else:
            return 0

    def is_short_url(self,url):
        # List of known short URL services
        known_shorteners = {
            "bit.ly", "goo.gl", "tinyurl.com", "is.gd", "cli.gs", "pic.gd", "tweetphoto",
            "DwarfURL.com", "ow.ly", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu",
            "tr.im", "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "BudURL.com", "short.to",
            "ping.fm", "Digg.com", "post.ly", "Just.as", ".tk", "bkite.com", "snipr.com",
            "flic.kr", "loopt.us", "doiop.com", "twitthis.com", "htxt.it", "AltURL.com",
            "RedirX.com", "DigBig.com", "short.ie", "u.mavrev.com", "kl.am", "wp.me", "u.nu",
            "rubyurl.com", "om.ly", "linkbee.com", "Yep.it", "posted.at", "xrl.us", "metamark.net",
            "sn.im", "hurl.ws", "eepurl.com", "idek.net", "urlpire.com", "chilp.it", "moourl.com",
            "snurl.com", "xr.com", "lin.cr", "EasyURI.com", "zz.gd", "ur1.ca", "URL.ie", "adjix.com",
            "twurl.cc", "s7y.us", "shrinkify", "EasyURL.net", "atu.ca", "sp2.ro", "Profile.to", "ub0.cc",
            "minurl.fr", "cort.as", "fire.to", "2tu.us", "twiturl.de", "to.ly", "BurnURL.com", "nn.nf", "clck.ru",
            "notlong.com", "thrdl.es", "spedr.com", "vl.am", "miniurl.com", "virl.com", "PiURL.com", "1url.com",
            "gri.ms", "tr.my", "Sharein.com", "urlzen.com", "fon.gs", "Shrinkify.com", "ri.ms", "b23.ru", "Fly2.ws",
            "xrl.in", "Fhurl.com", "wipi.es", "korta.nu", "shortna.me", "fa.b", "WapURL.co.uk", "urlcut.com", "6url.com",
            "abbrr.com", "SimURL.com", "klck.me", "x.se", "2big.at", "url.co.uk", "ewerl.com", "inreply.to", "TightURL.com",
            "a.gg", "tinytw.it", "zi.pe", "riz.gd", "hex.io", "fwd4.me", "bacn.me", "shrt.st", "ln-s.ru", "tiny.pl", "o-x.fr",
            "StartURL.com", "jijr.com", "shorl.com", "icanhaz.com", "updating.me", "kissa.be", "hellotxt.com", "pnt.me", "nsfw.in",
            "xurl.jp", "yweb.com", "urlkiss.com", "QLNK.net", "w3t.org", "lt.tl", "twirl.at", "zipmyurl.com", "urlot.com", "a.nf",
            "hurl.me", "URLHawk.com", "Tnij.org", "4url.cc", "firsturl.de", "Hurl.it", "sturly.com", "shrinkster.com", "ln-s.net",
            "go2cut.com", "liip.to", "shw.me", "XeeURL.com", "liltext.com", "lnk.gd", "xzb.cc", "linkbun.ch", "href.in", "urlbrief.com",
            "2ya.com", "safe.mn", "shrunkin.com", "bloat.me", "krunchd.com", "minilien.com", "ShortLinks.co.uk", "qicute.com", "rb6.me",
            "urlx.ie", "pd.am", "go2.me", "tinyarro.ws", "tinyvid.io", "lurl.no", "ru.ly", "lru.jp", "rickroll.it", "togoto.us", "ClickMeter.com",
            "hugeurl.com", "tinyuri.ca", "shrten.com", "shorturl.com", "Quip-Art.com", "urlao.com", "a2a.me", "tcrn.ch", "goshrink.com",
            "DecentURL.com", "decenturl.com", "zi.ma", "1link.in", "sharetabs.com", "shoturl.us", "fff.to", "hover.com", "lnk.in", "jmp2.net",
            "dy.fi", "urlcover.com", "2pl.us", "tweetburner.com", "u6e.de", "xaddr.com", "gl.am", "dfl8.me", "go.9nl.com", "gurl.es", "C-O.IN",
            "TraceURL.com", "liurl.cn", "MyURL.in", "urlenco.de", "ne1.net", "buk.me", "rsmonkey.com", "cuturl.com", "turo.us", "sqrl.it", "iterasi.net",
            "tiny123.com", "EsyURL.com", "urlx.org", "IsCool.net", "twitterpan.com", "GoWat.ch", "poprl.com", "njx.me"
        }

        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        # Normalize domain to handle cases like 'www.bit.ly'
        normalized_domain = domain.lower().replace('www.', '')

        return 1 if normalized_domain in known_shorteners else 0


    def calculate_similarity(self,domain, url):
        # Extract the domain from the URL using tldextract
        extracted_domain = tldextract.extract(url)
        url_domain = f"{extracted_domain.domain}.{extracted_domain.suffix}".lower()
        return fuzz.ratio(domain.lower(), url_domain)

    def find_most_similar_domain(self, url):
        max_similarity = 0
        most_similar_domain = None

        for index, row in self.well_known_domains_df.iterrows():
            # Access values in each row
            domain = row['domain']
            similarity = self.calculate_similarity(domain, url)
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_domain = domain

        return most_similar_domain, max_similarity/100


    def preprocess_and_extract_features(self, url):
        url_features = {}
    
        url_features['url_length'] = len(url)
        # Extract URL components
        full_domain, path, query = self.extract_url_components(url)
        url_features['domain'] = full_domain
        url_features['path_url'] = path
        url_features['query_url'] = query

        url_features['domain_length'] = len(full_domain) if full_domain else 0

        # Calculate various features
        url_features['url_kl_divergence'] = self.calculate_url_kl_divergence(url)
        url_features['domain_kl_divergence'] = self.calculate_domain_kl_divergence(url)
        url_features['path_kl_divergence'] = self.calculate_path_kl_divergence(url)
        url_features['query_kl_divergence'] = self.calculate_query_kl_divergence(url)
        url_features['query_path_kl_divergence'] = self.calculate_query_path_kl_divergence(url)
        url_features['num_special_symbols'] = self.count_special_symbols(url)
        url_features['contains_ip'] = self.contains_ip_address(url)
        url_features['tokens'] = self.tokenize_url(url)
        url_features['presence_of_suspicious_file_extensions'] = self.check_file_extensions(url)
        url_features['sub_domains_count'] = self.count_subdomains(url)
        url_features['digit_frequency'] = self.digit_frequency(url)
        url_features['count_tlds'] = self.count_tlds(url)
        url_features['is_short_url'] = self.is_short_url(url)
        url_features['similar_domain'] = self.find_most_similar_domain(url)[1]
        return url_features

    def predict_class(self, url):
        url_features = self.preprocess_and_extract_features(url)
        df = pd.DataFrame([url_features])

        numerical_features = [
            'domain_length', 'url_kl_divergence', 'num_special_symbols',
            'domain_kl_divergence', 'path_kl_divergence', 'query_kl_divergence', 
            'query_path_kl_divergence', 'presence_of_suspicious_file_extensions', 
            'sub_domains_count', 'digit_frequency', 'count_tlds', 'is_short_url', 'similar_domain'
        ]

        numerical_data_scaled = self.scaler.transform(df[numerical_features])
        X_tfidf = self.vectorizer.transform([url_features['tokens']])
        X_combined = hstack((X_tfidf, numerical_data_scaled))
        y_pred = self.model.predict(X_combined)
        decoded_prediction = self.label_encoder.inverse_transform(y_pred)

        return decoded_prediction[0]
