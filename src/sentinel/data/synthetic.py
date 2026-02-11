"""
src/sentinel/data/synthetic.py

Generate synthetic vulnerable code samples for training.
"""

import json
import logging
import random
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class VulnerableCodeSample:
    """A single vulnerable code sample."""
    id: str
    code: str
    vulnerability_type: str
    severity: str
    language: str
    complexity: str
    description: str
    cwe_id: str
    test_code: str = ""
    secure_version: str = ""


class SyntheticDatasetGenerator:
    """Generate synthetic vulnerable code samples."""
    
    # Code templates with vulnerabilities
    TEMPLATES = {
        'sql_injection': {
            'low': """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone() is not None
""",
            'medium': """
class UserDB:
    def __init__(self):
        self.conn = sqlite3.connect('users.db')
        self.cursor = self.conn.cursor()
    
    def find_user(self, username, email):
        query = f"SELECT * FROM users WHERE username='{username}' OR email='{email}'"
        self.cursor.execute(query)
        return self.cursor.fetchall()
    
    def update_profile(self, user_id, bio):
        query = f"UPDATE users SET bio='{bio}' WHERE id={user_id}"
        self.cursor.execute(query)
        self.conn.commit()
""",
            'high': """
class DatabaseManager:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
    
    def dynamic_query(self, table, conditions):
        # Build query dynamically based on conditions
        where_clause = " AND ".join([f"{k}='{v}'" for k, v in conditions.items()])
        query = f"SELECT * FROM {table} WHERE {where_clause}"
        return self.conn.cursor().execute(query).fetchall()
    
    def bulk_insert(self, table, records):
        for record in records:
            columns = ", ".join(record.keys())
            values = ", ".join([f"'{v}'" for v in record.values()])
            query = f"INSERT INTO {table} ({columns}) VALUES ({values})"
            self.conn.cursor().execute(query)
        self.conn.commit()
""",
        },
        
        'xss': {
            'low': """
from flask import Flask, request

app = Flask(__name__)

@app.route('/comment')
def show_comment():
    comment = request.args.get('text', '')
    return f"<div>{comment}</div>"
""",
            'medium': """
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/profile')
def profile():
    username = request.args.get('username', 'Guest')
    bio = request.args.get('bio', 'No bio')
    
    template = f'''
    <html>
        <h1>Profile: {username}</h1>
        <p>Bio: {bio}</p>
    </html>
    '''
    return render_template_string(template)
""",
            'high': """
class ForumRenderer:
    def __init__(self):
        self.posts = []
    
    def add_post(self, author, title, content):
        self.posts.append({
            'author': author,
            'title': title,
            'content': content
        })
    
    def render_posts(self):
        html = "<div class='forum'>"
        for post in self.posts:
            html += f'''
            <div class="post">
                <h2>{post['title']}</h2>
                <p class="author">By {post['author']}</p>
                <div class="content">{post['content']}</div>
            </div>
            '''
        html += "</div>"
        return html
""",
        },
        
        'command_injection': {
            'low': """
import os

def ping_host(hostname):
    command = f"ping -c 4 {hostname}"
    os.system(command)
""",
            'medium': """
import subprocess

def backup_database(db_name, backup_path):
    command = f"mysqldump {db_name} > {backup_path}"
    subprocess.call(command, shell=True)
    return f"Backup created at {backup_path}"
""",
            'high': """
class SystemManager:
    def __init__(self):
        self.log_file = "/var/log/app.log"
    
    def run_diagnostic(self, target):
        commands = [
            f"ping -c 1 {target}",
            f"traceroute {target}",
            f"nslookup {target}"
        ]
        
        results = []
        for cmd in commands:
            output = os.popen(cmd).read()
            results.append(output)
        
        return "\\n".join(results)
    
    def cleanup_logs(self, pattern):
        os.system(f"find /var/log -name '{pattern}' -delete")
""",
        },
        
        'path_traversal': {
            'low': """
def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()
""",
            'medium': """
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = f"/var/www/uploads/{filename}"
    return send_file(filepath)
""",
            'high': """
class FileManager:
    def __init__(self, base_dir="/var/www/files"):
        self.base_dir = base_dir
    
    def read_file(self, path):
        full_path = f"{self.base_dir}/{path}"
        with open(full_path, 'r') as f:
            return f.read()
    
    def write_file(self, path, content):
        full_path = f"{self.base_dir}/{path}"
        # Create directories if needed
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(content)
    
    def list_directory(self, path):
        full_path = f"{self.base_dir}/{path}"
        return os.listdir(full_path)
""",
        },
        
        'xxe': {
            'low': """
from lxml import etree

def parse_xml(xml_string):
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_string, parser)
    return tree
""",
            'medium': """
import xml.etree.ElementTree as ET

class ConfigParser:
    def __init__(self):
        self.config = {}
    
    def load_from_xml(self, xml_file):
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for child in root:
            self.config[child.tag] = child.text
        
        return self.config
""",
            'high': """
from lxml import etree

class XMLProcessor:
    def process_document(self, xml_data):
        parser = etree.XMLParser(resolve_entities=True)
        doc = etree.fromstring(xml_data, parser)
        
        # Extract data
        results = {}
        for elem in doc.iter():
            if elem.text:
                results[elem.tag] = elem.text
        
        return results
    
    def transform_xml(self, xml_data, xslt_data):
        xml_doc = etree.fromstring(xml_data)
        xslt_doc = etree.fromstring(xslt_data)
        transform = etree.XSLT(xslt_doc)
        return transform(xml_doc)
""",
        },
        
        'ssrf': {
            'low': """
import requests

def fetch_url(url):
    response = requests.get(url)
    return response.text
""",
            'medium': """
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    target_url = request.args.get('url')
    response = requests.get(target_url, timeout=5)
    return response.content
""",
            'high': """
class WebhookHandler:
    def __init__(self):
        self.webhooks = {}
    
    def register_webhook(self, name, url):
        self.webhooks[name] = url
    
    def trigger_webhook(self, name, data):
        url = self.webhooks.get(name)
        if url:
            response = requests.post(url, json=data)
            return response.status_code
    
    def test_endpoint(self, url):
        # Test if endpoint is reachable
        try:
            response = requests.get(url, timeout=2)
            return {"status": "reachable", "code": response.status_code}
        except:
            return {"status": "unreachable"}
""",
        },
    }
    
    # Secure versions
    SECURE_VERSIONS = {
        'sql_injection': {
            'low': """
def login(username, password):
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    return cursor.fetchone() is not None
""",
        },
        'xss': {
            'low': """
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

@app.route('/comment')
def show_comment():
    comment = request.args.get('text', '')
    return f"<div>{escape(comment)}</div>"
""",
        },
        'command_injection': {
            'low': """
import subprocess

def ping_host(hostname):
    # Validate hostname
    if not hostname.replace('.', '').replace('-', '').isalnum():
        raise ValueError("Invalid hostname")
    
    subprocess.run(['ping', '-c', '4', hostname], check=True)
""",
        },
        'path_traversal': {
            'low': """
import os

def read_file(filename):
    # Validate filename - no path traversal
    if '..' in filename or filename.startswith('/'):
        raise ValueError("Invalid filename")
    
    base_dir = "/var/www/safe_files"
    filepath = os.path.join(base_dir, filename)
    
    # Ensure path is within base_dir
    if not os.path.abspath(filepath).startswith(base_dir):
        raise ValueError("Path traversal detected")
    
    with open(filepath, 'r') as f:
        return f.read()
""",
        },
        'xxe': {
            'low': """
from lxml import etree

def parse_xml(xml_string):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    tree = etree.fromstring(xml_string, parser)
    return tree
""",
        },
        'ssrf': {
            'low': """
import requests
from urllib.parse import urlparse

def fetch_url(url):
    # Whitelist allowed domains
    allowed_domains = ['api.example.com', 'cdn.example.com']
    
    parsed = urlparse(url)
    if parsed.netloc not in allowed_domains:
        raise ValueError("Domain not allowed")
    
    response = requests.get(url, timeout=5)
    return response.text
""",
        },
    }
    
    # Test code templates
    TEST_TEMPLATES = {
        'sql_injection': """
import pytest

def test_login_valid_user():
    assert login('admin', 'password123') == True

def test_login_invalid_user():
    assert login('nobody', 'wrong') == False
""",
        'xss': """
import pytest

def test_comment_display():
    result = show_comment()
    assert '<div>' in result
""",
        'command_injection': """
import pytest

def test_ping_localhost():
    ping_host('localhost')
    # Should complete without error
""",
    }
    
    def __init__(self):
        """Initialize the generator."""
        self.cwe_mapping = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'xxe': 'CWE-611',
            'ssrf': 'CWE-918',
        }
    
    def generate_dataset(
        self, 
        num_samples: int = 1000,
        distribution: Dict[str, float] = None
    ) -> List[VulnerableCodeSample]:
        """
        Generate dataset of vulnerable code samples.
        
        Args:
            num_samples: Number of samples to generate
            distribution: Distribution of vulnerability types
            
        Returns:
            List of VulnerableCodeSample objects
        """
        if distribution is None:
            distribution = {
                'sql_injection': 0.25,
                'xss': 0.20,
                'command_injection': 0.20,
                'path_traversal': 0.15,
                'xxe': 0.10,
                'ssrf': 0.10,
            }
        
        dataset = []
        
        for i in range(num_samples):
            # Select vulnerability type based on distribution
            vuln_type = random.choices(
                list(distribution.keys()),
                weights=list(distribution.values())
            )[0]
            
            # Select complexity
            complexity = random.choice(['low', 'medium', 'high'])
            
            # Get template
            code = self.TEMPLATES[vuln_type][complexity]
            
            # Create sample
            sample = VulnerableCodeSample(
                id=f"{vuln_type}_{complexity}_{i:04d}",
                code=code.strip(),
                vulnerability_type=vuln_type,
                severity=self._get_severity(complexity),
                language='python',
                complexity=complexity,
                description=self._get_description(vuln_type),
                cwe_id=self.cwe_mapping[vuln_type],
                test_code=self.TEST_TEMPLATES.get(vuln_type, '').strip(),
                secure_version=self.SECURE_VERSIONS.get(vuln_type, {}).get(complexity, '').strip(),
            )
            
            dataset.append(sample)
        
        logger.info(f"Generated {len(dataset)} vulnerable code samples")
        return dataset
    
    def _get_severity(self, complexity: str) -> str:
        """Map complexity to severity."""
        mapping = {
            'low': 'medium',
            'medium': 'high',
            'high': 'critical',
        }
        return mapping.get(complexity, 'medium')
    
    def _get_description(self, vuln_type: str) -> str:
        """Get human-readable description."""
        descriptions = {
            'sql_injection': 'Unsanitized user input in SQL query allows SQL injection',
            'xss': 'Unescaped user input rendered in HTML allows cross-site scripting',
            'command_injection': 'User input passed to shell command allows command injection',
            'path_traversal': 'Unsanitized file path allows directory traversal',
            'xxe': 'XML parser allows external entity processing',
            'ssrf': 'User-controlled URL allows server-side request forgery',
        }
        return descriptions.get(vuln_type, 'Security vulnerability')
    
    def save_dataset(self, dataset: List[VulnerableCodeSample], output_path: str) -> None:
        """Save dataset to JSON file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump([asdict(sample) for sample in dataset], f, indent=2)
        
        logger.info(f"Saved dataset to {output_path}")
    
    def load_dataset(self, input_path: str) -> List[VulnerableCodeSample]:
        """Load dataset from JSON file."""
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        dataset = [VulnerableCodeSample(**sample) for sample in data]
        logger.info(f"Loaded {len(dataset)} samples from {input_path}")
        return dataset


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    generator = SyntheticDatasetGenerator()
    dataset = generator.generate_dataset(num_samples=100)
    generator.save_dataset(dataset, 'datasets/synthetic/training_data.json')
    
    print(f"Generated {len(dataset)} samples")
    print(f"\nSample code ({dataset[0].vulnerability_type}):")
    print(dataset[0].code)
