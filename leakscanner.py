#!/usr/bin/env python3
"""
LeakScanner - Dynamic Configuration-Based Leak Detection Tool
Scans GitHub repositories for leaked proprietary code and credentials
Per-customer configuration support
"""

import os
import sys
import json
import argparse
import logging
import re
from pathlib import Path
from datetime import datetime
import requests
import time
import warnings
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")
warnings.filterwarnings("ignore", category=UserWarning)



#Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()


# Optional: Google Gemini (can be disabled if not available)
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("[!] Warning: google-generativeai not installed. AI analysis disabled.")

# ============================================
# CONFIGURATION
# ============================================

CONFIG_DIR = "configs"
RESULTS_DIR = "results"
LOGS_DIR = "logs"

# ============================================
# CONFIGURATION LOADER
# ============================================

def load_config_for_customer(customer_id):
    """Load customer-specific configuration from JSON file"""
    path = Path(CONFIG_DIR) / f"{customer_id}.json"
    if not path.exists():
        raise SystemExit(f"Config not found for customer: {customer_id}\n   Expected: {path}")
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        logging.info(f"Loaded config for {config.get('customer_name', customer_id)}")
        return config
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON in config file: {e}")

# ============================================
# UTILITY FUNCTIONS
# ============================================

def setup_directories(customer_id):
    """Create necessary directories for results and logs"""
    (Path(RESULTS_DIR) / customer_id).mkdir(parents=True, exist_ok=True)
    Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)

def get_timestamp():
    """Get formatted timestamp for filenames"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def save_results(customer_id, findings, timestamp):
    """Save scan results to JSON and Markdown"""
    results_dir = Path(RESULTS_DIR) / customer_id
    
    # Save JSON
    json_path = results_dir / f"results_{timestamp}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "scan_date": datetime.now().isoformat(),
            "customer_id": customer_id,
            "total_findings": len(findings),
            "findings": findings
        }, f, indent=2)
    
    # Save Markdown report
    md_path = results_dir / f"report_{timestamp}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Leak Detection Report\n\n")
        f.write(f"**Customer ID:** {customer_id}\n")
        f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Total Findings:** {len(findings)}\n\n")
        f.write("---\n\n")
        
        for i, finding in enumerate(findings, 1):
            f.write(f"## Finding #{i}\n\n")
            f.write(f"- **Type:** {finding.get('type', 'unknown')}\n")
            f.write(f"- **Repository:** {finding.get('repo', 'N/A')}\n")
            f.write(f"- **Keyword/Pattern:** {finding.get('keyword', finding.get('pattern', 'N/A'))}\n")
            f.write(f"- **Severity:** {finding.get('severity', 'N/A')}\n")
            f.write(f"- **URL:** {finding.get('url', 'N/A')}\n")
            
            if 'verdict' in finding:
                f.write(f"- **Verdict:** {finding['verdict']}\n")
            
            f.write("\n---\n\n")
    
    return json_path, md_path

# ============================================
# GITHUB API FUNCTIONS (Simplified for local use)
# ============================================

def search_github_code(keyword, github_token=None, repo_filter="", limit=30):
    """Search GitHub for code containing the keyword"""
    if not github_token:
        logging.warning("No GitHub token provided, using unauthenticated API (limited)")
    
    url = "https://api.github.com/search/code"
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    
    search_query = keyword
    if repo_filter:
        search_query = f"{keyword} repo:{repo_filter}"
    
    params = {
        "q": search_query,
        "per_page": min(limit, 30)
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error searching GitHub Code: {e}")
        return None

def get_file_content(repo_full_name, file_path, github_token=None):
    """Fetch the raw content of a file from GitHub"""
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{file_path}"
    headers = {
        "Accept": "application/vnd.github.v3.raw"
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching file content: {e}")
        return None

def extract_context_lines(file_content, keyword, context_lines=100):
    """Extract lines around the keyword match"""
    lines = file_content.split('\n')
    keyword_lower = keyword.lower()
    
    matches = []
    for i, line in enumerate(lines):
        if keyword_lower in line.lower():
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            context = '\n'.join(lines[start:end])
            matches.append({
                'line_number': i + 1,
                'context': context,
                'total_lines': len(lines),
                'matched_line': line
            })
    
    return matches

def check_regex_patterns(content, patterns):
    """Check content against configured regex patterns"""
    findings = []
    for pattern_config in patterns:
        if not pattern_config.get('enabled', True):
            continue
        
        pattern = pattern_config['pattern']
        try:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'pattern_name': pattern_config['name'],
                    'pattern_description': pattern_config.get('description', ''),
                    'severity': pattern_config.get('severity', 'medium'),
                    'matched_text': match.group(0)[:100],  # Limit to 100 chars
                    'position': match.start()
                })
        except re.error as e:
            logging.error(f"Invalid regex pattern '{pattern_config['name']}': {e}")
    
    return findings

# ============================================
# AI ANALYSIS (Optional)
# ============================================

def analyze_with_ai(content, keyword, customer_name, api_key=None):
    """Analyze content with Gemini AI if available"""
    if not GEMINI_AVAILABLE or not api_key:
        return {
            'verdict': 'unknown',
            'confidence': 'n/a',
            'reasoning': 'AI analysis not available (no API key or SDK not installed)'
        }
    
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""Analyze if this code appears to belong to {customer_name}.

Keyword found: {keyword}

Code snippet (first 500 chars):
{content[:500]}

Respond with:
VERDICT: [YES/NO/UNCERTAIN]
CONFIDENCE: [High/Medium/Low]
REASONING: [Brief explanation]
"""
        
        response = model.generate_content(prompt)
        text = response.text
        
        # Parse response
        verdict = 'uncertain'
        if 'VERDICT: YES' in text:
            verdict = 'yes'
        elif 'VERDICT: NO' in text:
            verdict = 'no'
        
        confidence = 'medium'
        if 'CONFIDENCE: High' in text:
            confidence = 'high'
        elif 'CONFIDENCE: Low' in text:
            confidence = 'low'
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'reasoning': text
        }
    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        return {
            'verdict': 'error',
            'confidence': 'n/a',
            'reasoning': str(e)
        }

# ============================================
# MAIN SCANNER LOGIC
# ============================================

def run_scan(config, args):
    """Main scanning logic"""
    customer_id = config.get('customer_id')
    customer_name = config.get('customer_name', customer_id)
    keywords = config.get('keywords', [])
    patterns = [p for p in config.get('regex_patterns', []) if p.get('enabled', True)]
    scan_settings = config.get('scan_settings', {})
    
    context_lines = scan_settings.get('context_lines', 100)
    max_results = args.limit if args.limit else scan_settings.get('max_results_per_keyword', 5)
    search_types = scan_settings.get('search_types', ['code'])
    exclude_repos = scan_settings.get('exclude_repos', [])
    
    # Get API credentials from environment
    github_token = os.environ.get(config.get('api_credentials', {}).get('github_token_env', 'GITHUB_TOKEN'))
    gemini_key = os.environ.get(config.get('api_credentials', {}).get('gemini_key_env', 'GEMINI_API_KEY'))
    
    if not github_token:
        print("[!] Warning: No GitHub token found. API rate limits will be very restrictive.")
        logging.warning("No GitHub token provided")
    
    print(f"[✓] Loaded config for {customer_name}")
    print(f"[+] Keywords: {', '.join(keywords)}")
    print(f"[+] Context lines: {context_lines}")
    print(f"[+] Max results per keyword: {max_results}")
    print(f"[+] Search types: {', '.join(search_types)}")
    print(f"[+] Starting scan...\n")
    
    all_findings = []
    total_items_checked = 0
    
    for keyword in keywords:
        print(f"Searching for: '{keyword}'...")
        logging.info(f"Scanning keyword: {keyword}")
        
        # Only search code for now (to keep it simple and local-friendly)
        if 'code' in search_types:
            code_results = search_github_code(keyword, github_token, limit=max_results)
            
            if code_results and 'items' in code_results:
                items = code_results.get('items', [])
                print(f"   ✓ Found {len(items)} code results")
                
                for idx, item in enumerate(items, 1):
                    repo_name = item['repository']['full_name']
                    
                    # Skip excluded repos
                    if any(excl in repo_name for excl in exclude_repos):
                        print(f"   ⊗ Skipping excluded repo: {repo_name}")
                        continue
                    
                    file_path = item['path']
                    html_url = item['html_url']
                    
                    print(f"   [{idx}/{len(items)}] Checking: {repo_name}/{file_path}")
                    total_items_checked += 1
                    
                    # Get file content
                    file_content = get_file_content(repo_name, file_path, github_token)
                    
                    if file_content:
                        # Extract context
                        matches = extract_context_lines(file_content, keyword, context_lines)
                        
                        if matches:
                            match = matches[0]
                            
                            # Check regex patterns
                            pattern_findings = check_regex_patterns(file_content, patterns)
                            
                            # AI analysis (optional)
                            ai_result = {'verdict': 'not_analyzed'}
                            if gemini_key and not args.test_mode:
                                ai_result = analyze_with_ai(match['context'], keyword, customer_name, gemini_key)
                            
                            finding = {
                                'type': 'code',
                                'keyword': keyword,
                                'repo': repo_name,
                                'file': file_path,
                                'url': html_url,
                                'line': match['line_number'],
                                'matched_line': match['matched_line'],
                                'severity': 'medium',
                                'verdict': ai_result.get('verdict', 'unknown'),
                                'confidence': ai_result.get('confidence', 'n/a'),
                                'pattern_matches': pattern_findings
                            }
                            
                            all_findings.append(finding)
                            
                            # Determine severity
                            if pattern_findings:
                                severities = [p['severity'] for p in pattern_findings]
                                if 'critical' in severities:
                                    finding['severity'] = 'critical'
                                    print(f"      [!] CRITICAL: Pattern match detected")
                                elif 'high' in severities:
                                    finding['severity'] = 'high'
                                    print(f"      [!] HIGH: Pattern match detected")
                    
                    time.sleep(2)  # Rate limiting
            else:
                print(f"   ✗ No results found")
        
        print()
    print(f"[+] Finished scanning {len(keywords)} keyword(s), checked {total_items_checked} file(s)")
    logging.info(f"Scanned {len(keywords)} keyword(s), checked {total_items_checked} file(s)")
    return all_findings

def run_test_mode(config):
    """Generate mock findings for testing"""
    customer_name = config.get('customer_name', 'TestCompany')
    keywords = config.get('keywords', ['TestKeyword'])
    
    print(f"[✓] Running in TEST MODE for {customer_name}")
    print(f"[+] Generating mock findings...\n")
    
    findings = []
    for keyword in keywords[:2]:  # Limit to 2 keywords
        findings.append({
            'type': 'code',
            'keyword': keyword,
            'repo': f'{customer_name.lower()}-demo-org/{customer_name.lower()}-leak-demo',
            'file': '.env',
            'url': f'https://github.com/{customer_name.lower()}-demo-org/{customer_name.lower()}-leak-demo/blob/main/.env',
            'line': 12,
            'matched_line': f'{keyword}_API_KEY=abc123xyz',
            'severity': 'high',
            'verdict': 'suspected',
            'confidence': 'medium',
            'pattern_matches': [
                {
                    'pattern_name': 'api_key',
                    'pattern_description': 'Generic API Key',
                    'severity': 'high',
                    'matched_text': 'API_KEY=abc123xyz'
                }
            ]
        })
        
        findings.append({
            'type': 'code',
            'keyword': keyword,
            'repo': 'john-doe/personal-project',
            'file': 'config.py',
            'url': 'https://github.com/john-doe/personal-project/blob/main/config.py',
            'line': 45,
            'matched_line': f'# {keyword} internal system',
            'severity': 'medium',
            'verdict': 'uncertain',
            'confidence': 'low',
            'pattern_matches': []
        })
    
    print(f"[!] Generated {len(findings)} mock findings\n")
    return findings

# ============================================
# CLI INTERFACE
# ============================================

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='LeakScanner - Dynamic configuration-based leak detection tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python leakscanner.py --customer acme-123
  python leakscanner.py --customer tharupathib-001 --test-mode
  python leakscanner.py --customer acme-123 --limit 10 --out-json custom_results.json
        """
    )
    
    parser.add_argument(
        '--customer',
        required=True,
        help='Customer ID (must match a config file in configs/ directory)'
    )
    
    parser.add_argument(
        '--test-mode',
        action='store_true',
        help='Run in test mode with mock data (no actual GitHub API calls)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Maximum number of results per keyword (overrides config)'
    )
    
    parser.add_argument(
        '--out-json',
        help='Custom output JSON file path (default: results/<customer>/results_<timestamp>.json)'
    )
    
    return parser.parse_args()

# ============================================
# MAIN ENTRY POINT
# ============================================

def main():
    """Main entry point"""
    print("="*70)
    print("LeakScanner - Dynamic Configuration-Based Leak Detection")
    print("="*70)
    print()

    start_time = time.time()
    
    # Parse arguments
    args = parse_arguments()
    
    # Setup directories
    setup_directories(args.customer)
    
    # Setup logging
    log_file = Path(LOGS_DIR) / f"{args.customer}.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    logging.info(f"="*50)
    logging.info(f"Starting scan for customer: {args.customer}")
    logging.info(f"Test mode: {args.test_mode}")
    
    try:
        # Load configuration
        config = load_config_for_customer(args.customer)
        
        # Run scan
        if args.test_mode:
            findings = run_test_mode(config)
        else:
            findings = run_scan(config, args)
        
        # Report results
        print("="*70)
        print(f"[!] Found {len(findings)} potential leaks")
        print("="*70)
        print()
        
        if findings:
            # Group by severity
            critical = [f for f in findings if f.get('severity') == 'critical']
            high = [f for f in findings if f.get('severity') == 'high']
            medium = [f for f in findings if f.get('severity') == 'medium']
            
            if critical:
                print(f"CRITICAL: {len(critical)} findings")
            if high:
                print(f"HIGH: {len(high)} findings")
            if medium:
                print(f"MEDIUM: {len(medium)} findings")
            print()
            
            # Show summary
            print("Summary:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. [{finding['severity'].upper()}] {finding['repo']}/{finding.get('file', 'N/A')}")
                print(f"     Keyword: {finding['keyword']} | Verdict: {finding.get('verdict', 'N/A')}")
            
            if len(findings) > 5:
                print(f"  ... and {len(findings) - 5} more")
            print()
        
        # Save results
        timestamp = get_timestamp()
        
        if args.out_json:
            # Custom output path
            json_path = Path(args.out_json)
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "scan_date": datetime.now().isoformat(),
                    "customer_id": args.customer,
                    "total_findings": len(findings),
                    "findings": findings
                }, f, indent=2)
            print(f"Results saved to {json_path}")
        else:
            # Standard output
            json_path, md_path = save_results(args.customer, findings, timestamp)
            print(f"Results saved to:")
            print(f"    JSON: {json_path}")
            print(f"    Report: {md_path}")
        
        print(f"[✓] Logs saved to: {log_file}")
        print()
        
        logging.info(f"Scan complete. Found {len(findings)} potential leaks")
        logging.info(f"Results saved to: {json_path}")
        elapsed = time.time() - start_time
        print(f"[⏱] Scan finished in {elapsed:.1f} seconds")
        logging.info(f"Scan duration: {elapsed:.1f} seconds")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        logging.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        logging.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
