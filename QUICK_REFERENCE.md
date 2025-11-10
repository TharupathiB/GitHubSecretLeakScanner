# LeakScanner - Quick Reference Card

## One-Line Commands

```bash
# Basic scan
python leakscanner.py --customer acme-123

# Test mode
python leakscanner.py --customer acme-123 --test-mode

# With limits
python leakscanner.py --customer acme-123 --limit 10

# Custom output
python leakscanner.py --customer acme-123 --out-json my_results.json
```

---

## File Locations

```
configs/<customer-id>.json       # Configuration
results/<customer-id>/*.json     # Scan results
results/<customer-id>/*.md       # Reports
logs/<customer-id>.log           # Logs
```

---

## Config Template (Minimal)

```json
{
  "customer_id": "my-id",
  "customer_name": "MyCompany",
  "keywords": ["Keyword1", "Keyword2"],
  "regex_patterns": [],
  "scan_settings": {
    "context_lines": 100,
    "max_results_per_keyword": 5
  }
}
```

---

## Environment Variables

```bash
export GITHUB_TOKEN="ghp_..."      # Optional but recommended
export GEMINI_API_KEY="..."        # Optional (for AI)
```

---

## Common Patterns

```json
"regex_patterns": [
  {
    "name": "github_token",
    "pattern": "ghp_[a-zA-Z0-9]{36}",
    "severity": "critical",
    "enabled": true
  },
  {
    "name": "aws_key",
    "pattern": "AKIA[0-9A-Z]{16}",
    "severity": "critical",
    "enabled": true
  }
]
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Config not found | Create `configs/<id>.json` |
| No GitHub token | Set `GITHUB_TOKEN` env var |
| Rate limit | Add GitHub token or wait |
| AI disabled | Install `google-generativeai` |

---

## Output Examples

**JSON:** `results/acme-123/results_20251109_143022.json`  
**Markdown:** `results/acme-123/report_20251109_143022.md`  
**Logs:** `logs/acme-123.log`

---

## Quick Setup (30 seconds)

```bash
# 1. Install
pip install requests google-generativeai

# 2. Create config
cp configs/acme-123.json configs/mycompany.json
# Edit mycompany.json

# 3. Run
python leakscanner.py --customer mycompany --test-mode
```

---

## Performance

- **1 keyword:** ~30 seconds
- **5 keywords:** ~5 minutes
- **10 keywords:** ~15 minutes

Rate limiting: 2 seconds between requests

---

## CLI Options Summary

```
--customer <id>        Required: Customer config ID
--test-mode            Optional: Use mock data
--limit <n>            Optional: Max results per keyword
--out-json <path>      Optional: Custom JSON output
```

---

**Need Help?** Check `README_SETUP.md` for detailed documentation
