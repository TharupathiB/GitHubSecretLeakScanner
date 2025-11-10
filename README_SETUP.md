# LeakScanner - Setup & Usage Guide

## Overview

# LeakScanner v1.0 — Secure Multi-Tenant Leak Detection Tool

LeakScanner is a configuration-driven tool that scans GitHub code for potential leaks of
proprietary information and secrets (API keys, tokens, internal systems, emails, etc.).
Each customer (tenant) has its own config file with brand keywords, regex patterns and
scan rules, so the same engine can protect multiple organizations without changing code.

The tool supports:
- Multi-tenant configs (e.g. Medellin Travels, Acme Polythene, Nike, ESPN, DP Logistics)
- Local-first scanning using the GitHub API
- Regex-based secret detection (API keys, AWS keys, internal emails)
- Optional AI-assisted verdicts via Google Gemini
- Per-tenant JSON + Markdown reports and logs
- Test mode with mock findings for safe demos and offline evaluation


**LeakScanner** is a configurable, per-customer leak detection tool that scans GitHub repositories for leaked proprietary code and credentials.

**Key Features:**
- Dynamic per-customer configuration
- Regex pattern matching for credentials
- Optional AI analysis with Google Gemini
- Local execution (no AWS required)
- Test mode for demos
- JSON and Markdown reports

---

## Directory Structure

```
leakscanner/
├── leakscanner.py          # Main scanner script
├── configs/                # Customer configurations
│   ├── acme-123.json
│   └── tharupathib-001.json
├── results/                # Scan results (auto-created)
│   ├── acme-123/
│   │   ├── results_20251109_143022.json
│   │   └── report_20251109_143022.md
│   └── tharupathib-001/
├── logs/                   # Scan logs (auto-created)
│   ├── acme-123.log
│   └── tharupathib-001.log
└── README_SETUP.md         # This file
```

---

## Quick Start


### 1. Install Dependencies

```bash
pip install requests google-generativeai
```

**Note:** `google-generativeai` is optional. Scanner works without it (AI analysis disabled).

### 2. Create Customer Configuration

Create a JSON file in `configs/` directory:

**Example: `configs/mycompany-001.json`**

```json
{
  "customer_id": "mycompany-001",
  "customer_name": "MyCompany",
  "description": "My company description",
  
  "keywords": [
    "MyCompany",
    "MyProduct",
    "MyInternalSystem"
  ],
  
  "regex_patterns": [
    {
      "name": "github_token",
      "pattern": "ghp_[a-zA-Z0-9]{36}",
      "description": "GitHub Personal Access Token",
      "severity": "critical",
      "enabled": true
    }
  ],
  
  "scan_settings": {
    "context_lines": 100,
    "max_results_per_keyword": 5,
    "search_types": ["code"],
    "exclude_repos": []
  },
  
  "api_credentials": {
    "github_token_env": "GITHUB_TOKEN",
    "gemini_key_env": "GEMINI_API_KEY"
  }
}
```

### 3. Set Environment Variables (Optional)

```bash
# For GitHub API (recommended)
export GITHUB_TOKEN="ghp_your_token_here"

# For AI analysis (optional)
export GEMINI_API_KEY="your_gemini_key_here"
```

**Without tokens:**
- GitHub: Uses unauthenticated API (60 requests/hour limit)
- Gemini: AI analysis disabled

### 4. Run Scanner

```bash
# Basic scan
python leakscanner.py --customer mycompany-001

# Test mode (no API calls, uses mock data)
python leakscanner.py --customer mycompany-001 --test-mode

# With custom limits
python leakscanner.py --customer mycompany-001 --limit 10

# Custom output file
python leakscanner.py --customer mycompany-001 --out-json my_results.json
```

---

## Configuration File Reference

### Complete Configuration Schema

```json
{
  "customer_id": "unique-id",
  "customer_name": "Display Name",
  "description": "Customer description",
  
  "keywords": [
    "Keyword1",
    "Keyword2"
  ],
  
  "regex_patterns": [
    {
      "name": "pattern_name",
      "pattern": "regex_pattern_here",
      "description": "What this pattern detects",
      "severity": "critical|high|medium|low",
      "enabled": true
    }
  ],
  
  "scan_settings": {
    "context_lines": 100,
    "max_results_per_keyword": 5,
    "search_types": ["code", "issues", "commits", "repos", "topics"],
    "exclude_repos": ["repo-to-skip"]
  },
  
  "api_credentials": {
    "github_token_env": "GITHUB_TOKEN",
    "gemini_key_env": "GEMINI_API_KEY"
  },
  
  "notification_settings": {
    "enabled": false,
    "email": "security@company.com",
    "alert_on_severity": ["critical", "high"]
  }
}
```

### Common Regex Patterns

```json
{
  "regex_patterns": [
    {
      "name": "github_token",
      "pattern": "ghp_[a-zA-Z0-9]{36}",
      "severity": "critical"
    },
    {
      "name": "aws_key",
      "pattern": "AKIA[0-9A-Z]{16}",
      "severity": "critical"
    },
    {
      "name": "api_key",
      "pattern": "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
      "severity": "high"
    },
    {
      "name": "slack_webhook",
      "pattern": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
      "severity": "high"
    },
    {
      "name": "private_key",
      "pattern": "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
      "severity": "critical"
    },
    {
      "name": "database_url",
      "pattern": "(?i)(mongodb|mysql|postgres)://[^\\s]+",
      "severity": "high"
    },
    {
      "name": "jwt_token",
      "pattern": "eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*",
      "severity": "medium"
    }
  ]
}
```

---

## Command-Line Options

### Required

```bash
--customer <id>        Customer ID matching a config file in configs/
```

### Optional

```bash
--test-mode           Run with mock data (no GitHub API calls)
--limit <n>           Max results per keyword (overrides config)
--out-json <path>     Custom JSON output path
```

---

## Output Files

### JSON Results

**Location:** `results/<customer_id>/results_<timestamp>.json`

```json
{
  "scan_date": "2025-11-09T14:30:22.123456",
  "customer_id": "acme-123",
  "total_findings": 3,
  "findings": [
    {
      "type": "code",
      "keyword": "AcmeApparel",
      "repo": "john-doe/leaked-repo",
      "file": "config.py",
      "url": "https://github.com/...",
      "line": 45,
      "matched_line": "ACME_API_KEY = 'secret123'",
      "severity": "high",
      "verdict": "yes",
      "confidence": "high",
      "pattern_matches": [
        {
          "pattern_name": "api_key",
          "severity": "high",
          "matched_text": "API_KEY = 'secret123'"
        }
      ]
    }
  ]
}
```

### Markdown Report

**Location:** `results/<customer_id>/report_<timestamp>.md`

Human-readable report with:
- Scan metadata
- Findings summary
- Detailed finding information

### Log Files

**Location:** `logs/<customer_id>.log`

Contains:
- Scan start/end times
- API calls made
- Errors encountered
- Results saved locations

---

## Security Best Practices

### 1. Never Commit API Keys

```bash
# Add to .gitignore
.env
*.log
results/
```

### 2. Use Environment Variables

```bash
# Linux/Mac
export GITHUB_TOKEN="your_token"

# Windows
set GITHUB_TOKEN=your_token
```

### 3. Rotate Tokens Regularly

- GitHub tokens: Every 90 days
- Gemini keys: As needed

### 4. Limit Token Permissions

GitHub token should have **ONLY**:
- `public_repo` (read public repositories)
- No write access
- No private repo access

---

## Testing

### Test Mode

```bash
python leakscanner.py --customer acme-123 --test-mode
```

**What it does:**
-  Generates mock findings
-  No API calls
-  Tests report generation
-  Fast execution

### Verify Setup

```bash
# 1. Check config exists
ls configs/acme-123.json

# 2. Run test mode
python leakscanner.py --customer acme-123 --test-mode

# 3. Check outputs
ls results/acme-123/
ls logs/
```

---

## Troubleshooting

### "Config not found for customer"

**Problem:** Config file doesn't exist

**Solution:**
```bash
# Check file exists
ls configs/<customer-id>.json

# Create if missing
cp configs/acme-123.json configs/<customer-id>.json
```

### "No GitHub token found"

**Problem:** Environment variable not set

**Solution:**
```bash
# Set environment variable
export GITHUB_TOKEN="ghp_..."

# Verify
echo $GITHUB_TOKEN
```

### "Rate limit exceeded"

**Problem:** Too many API calls

**Solution:**
- Use GitHub token (increases limit)
- Reduce `--limit` value
- Wait 1 hour for reset

### "AI analysis not available"

**Problem:** Gemini SDK not installed or no API key

**Solution:**
```bash
# Install SDK
pip install google-generativeai

# Set API key
export GEMINI_API_KEY="..."
```

**Note:** Scanner works without AI analysis

---

## Performance

### API Rate Limits

| API | Unauthenticated | Authenticated |
|-----|-----------------|---------------|
| GitHub Code Search | 10/min | 30/min |
| GitHub Content | 60/hour | 5000/hour |
| Gemini AI | N/A | 15/min (free tier) |

### Scan Duration

- **Small scan** (1-2 keywords): 1-2 minutes
- **Medium scan** (5 keywords): 5-10 minutes
- **Large scan** (10+ keywords): 15-30 minutes

**Factors:**
- Number of keywords
- Results per keyword
- Rate limiting delays (2 seconds between requests)
- AI analysis enabled/disabled

---

## Migration from Phase 1

### Changes from Original Script

| Feature | Phase 1 | LeakScanner |
|---------|---------|-------------|
| Config | Hardcoded | JSON files |
| Per-customer | No | Yes |
| CLI | No | Yes |
| Output | Console | JSON + MD + Logs |
| Test mode | No | Yes |
| Patterns | Fixed | Configurable regex |

### Migration Steps

1. **Extract your configuration:**
   ```python
   # Old (hardcoded)
   KEYWORDS = ["MyCompany", "MyProduct"]
   
   # New (config file)
   {
     "keywords": ["MyCompany", "MyProduct"]
   }
   ```

2. **Create config file:**
   ```bash
   cp configs/acme-123.json configs/mycompany-001.json
   # Edit with your settings
   ```

3. **Run new scanner:**
   ```bash
   python leakscanner.py --customer mycompany-001
   ```

---

## 📚 Examples

### Example 1: Basic Scan

```bash
python leakscanner.py --customer acme-123
```

**Output:**
```
======================================================================
LeakScanner - Dynamic Configuration-Based Leak Detection
======================================================================

[+] Loaded config for AcmePoly
[+] Keywords: AcmePoly, AcmeERP, AcmeFactory
[+] Context lines: 100
[+] Max results per keyword: 5
[+] Starting scan...

 Searching for: 'AcmePoly'...
   + Found 2 code results
   [1/2] Checking: john-doe/test-repo/config.py
   [2/2] Checking: jane-smith/personal-project/.env
      [!] CRITICAL: Pattern match detected

======================================================================
[!] Found 2 potential leaks
======================================================================

CRITICAL: 1 findings
MEDIUM: 1 findings

Summary:
  1. [CRITICAL] jane-smith/personal-project/.env
     Keyword: AcmeApparel | Verdict: yes
  2. [MEDIUM] john-doe/test-repo/config.py
     Keyword: AcmeApparel | Verdict: uncertain

[+] Results saved to:
    JSON: results/acme-123/results_20251109_143022.json
    Report: results/acme-123/report_20251109_143022.md
[+] Logs saved to: logs/acme-123.log
```

### Example 2: Test Mode

```bash
python leakscanner.py --customer tharupathib-001 --test-mode
```

**Output:**
```
======================================================================
LeakScanner - Dynamic Configuration-Based Leak Detection
======================================================================

[+] Running in TEST MODE for TharupathiBan
[+] Generating mock findings...

[!] Generated 4 mock findings

======================================================================
[!] Found 4 potential leaks
======================================================================

HIGH: 2 findings
MEDIUM: 2 findings

[+] Results saved to: results/tharupathib-001/results_20251109_143530.json
```

### Example 3: Custom Limit

```bash
python leakscanner.py --customer acme-123 --limit 10
```

Scans up to 10 results per keyword (overrides config setting).

---

## Next Steps

### AWS Lambda Deployment

To deploy to Lambda:
1. Add Lambda handler wrapper
2. Move to AWS Secrets Manager for keys
3. Use EventBridge for scheduling
4. Store results in S3/DynamoDB

### Enhanced Features

- [ ] Multi-threading for faster scans
- [ ] Email/Slack notifications
- [ ] Web dashboard
- [ ] Historical trending
- [ ] False positive tracking

---
## Known Environment Warnings (Safe to Ignore)

On some macOS Python 3.9 environments, the following warnings may appear:

- `NotOpenSSLWarning: urllib3 v2 only supports OpenSSL 1.1.1+, currently 'ssl' is LibreSSL 2.8.3`
- `FutureWarning: You are using a Python version (3.9.x) past its end of life`

These are related to the local Python installation, not to LeakScanner itself.
On Windows or Python 3.10+ environments, these warnings will not appear.

They do not affect the core functionality of the tool.
Upgrading to Python 3.11+ or running on a Windows environment
removes them completely.

## Support

For issues or questions:
1. Check logs in `logs/<customer-id>.log`
2. Run in test mode to verify setup
3. Review configuration file syntax

---

**Version:** 2.0 (Dynamic Configuration)  
**Last Updated:** November 2025  
**Status:** Production Ready
