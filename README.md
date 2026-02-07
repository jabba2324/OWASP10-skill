# OWASP Top 10 Security Scanner for Claude Code

A Claude Code plugin that scans your codebase for security vulnerabilities based on the OWASP Top 10 (2025).

## Quick Start

### Step 1: Add the Marketplace

In Claude Code, run:

```
/plugin marketplace add jabba2324/OWASP10-skill
```

### Step 2: Install the Plugin

```
/plugin install owasp10
```

### Step 3: Run a Security Scan

```
/owasp10
```

That's it! The skill will analyze your codebase and report any security vulnerabilities found.

## Usage

| Command | Description |
|---------|-------------|
| `/owasp10` | Run a full OWASP Top 10 security scan |
| `/owasp10 A03` | Scan for a specific category (e.g., Supply Chain) |
| `/owasp10 --path src/` | Scan a specific directory |

## What It Detects

| Code | Category | Examples |
|------|----------|----------|
| A01 | Broken Access Control | Missing auth checks, IDOR, path traversal, SSRF |
| A02 | Security Misconfiguration | Debug mode, permissive CORS, verbose errors |
| A03 | Software Supply Chain Failures | Outdated deps, unsigned packages, CI/CD risks |
| A04 | Cryptographic Failures | Weak hashing (MD5/SHA1), hardcoded secrets |
| A05 | Injection | SQL, Command, XSS, LDAP, NoSQL injection |
| A06 | Insecure Design | Missing rate limiting, weak passwords |
| A07 | Authentication Failures | Weak sessions, credential exposure |
| A08 | Software/Data Integrity Failures | Insecure deserialization, unsigned updates |
| A09 | Logging and Alerting Failures | Missing audit logs, sensitive data in logs |
| A10 | Mishandling Exceptional Conditions | Failing open, empty catch blocks, ReDoS |

## Supported Languages

- JavaScript / TypeScript
- Python
- Java
- PHP
- Go
- Ruby

## Example Output

```
## Security Scan Results

### Summary
- Critical: 2 issues
- High: 3 issues
- Medium: 5 issues
- Low: 2 issues

### Critical Issues

#### [A05] SQL Injection in user authentication
- **File**: src/auth/login.js:45
- **Code**: `db.query("SELECT * FROM users WHERE id = " + userId)`
- **Risk**: Attackers can extract or modify database contents
- **Fix**: Use parameterized queries
```

## Alternative Installation (Manual)

If you prefer not to use the plugin marketplace:

**Per-project:**
```bash
git clone https://github.com/jabba2324/OWASP10-skill.git
mkdir -p .claude/skills
cp -r OWASP10-skill/plugins/owasp10/skills/owasp10 .claude/skills/
```

**Global (all projects):**
```bash
git clone https://github.com/jabba2324/OWASP10-skill.git
mkdir -p ~/.claude/skills
cp -r OWASP10-skill/plugins/owasp10/skills/owasp10 ~/.claude/skills/
```

## Requirements

- [Claude Code](https://claude.ai/download) installed

## License

MIT
