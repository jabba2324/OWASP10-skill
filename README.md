# OWASP Top 10 Security Scanner Skill for Claude Code

A Claude Code skill that helps developers detect common security vulnerabilities based on the OWASP Top 10 (2025).

## Installation

### Option 1: Install via Plugin Marketplace (Recommended)

Add the marketplace and install the plugin directly in Claude Code:

```
/plugin marketplace add jabba2324/OWASP10-skill
/plugin install owasp10
```

### Option 2: Copy to your project (per-project)

Copy the skill directory to your project's `.claude/skills/` directory:

```bash
git clone https://github.com/jabba2324/OWASP10-skill.git
cp -r OWASP10-skill/plugins/owasp10/.claude/skills/owasp10 .claude/skills/
```

### Option 3: Install globally (all projects)

Copy the skill to your global Claude Code skills directory:

```bash
git clone https://github.com/jabba2324/OWASP10-skill.git
cp -r OWASP10-skill/plugins/owasp10/.claude/skills/owasp10 ~/.claude/skills/
```

## Usage

Once installed, invoke the skill in Claude Code:

```
/owasp10
```

### Command Options

| Command | Description |
|---------|-------------|
| `/owasp10` | Run a full OWASP Top 10 security scan |
| `/owasp10 A03` | Scan for a specific category (e.g., Supply Chain) |
| `/owasp10 --path src/` | Scan a specific directory |

## What It Detects

The skill scans for all OWASP Top 10 (2025) vulnerability categories:

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

```markdown
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

## Requirements

- [Claude Code CLI](https://claude.ai/claude-code) installed and configured

## License

MIT
