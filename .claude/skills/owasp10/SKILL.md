---
name: owasp10
description: Scan code for OWASP Top 10 security vulnerabilities
---

# Security Vulnerability Scanner - OWASP Top 10

Analyze code for security vulnerabilities based on the OWASP Top 10 (2025). This skill performs a comprehensive security audit of the codebase.

## Instructions

When the user invokes this skill, perform a thorough security analysis of their codebase by searching for patterns associated with each OWASP Top 10 vulnerability category. For each finding, provide:

1. **Severity**: Critical, High, Medium, or Low
2. **Location**: File path and line number
3. **Vulnerability Type**: Which OWASP category it falls under
4. **Description**: What the vulnerability is and why it's dangerous
5. **Remediation**: How to fix the issue with code examples

## OWASP Top 10 (2025) Detection Patterns

### A01:2025 - Broken Access Control

The #1 most critical risk. Now includes SSRF (previously A10:2021).

**Missing authorization checks:**
- Routes/endpoints without authentication middleware
- Direct object references without ownership validation
- Missing role-based access control (RBAC) checks
- Insecure direct object references (IDOR)

**Detection patterns:**
```
# Missing auth middleware
app.get('/admin', (req, res) => // No auth check
router.post('/user/:id', // Direct ID access without validation

# Insecure file access / Path traversal
fs.readFile(req.params.filename)
new File(userInput) // Java path traversal
Path.Combine(basePath, userInput) // C#

# Missing ownership checks
User.findById(req.params.id) // Without req.user.id comparison

# SSRF - User-controlled URLs (moved from A10:2021)
fetch(req.body.url)
requests.get(user_url)
urllib.urlopen(user_input)
HttpClient.GetAsync(userUrl)
file_get_contents($url)

# Internal network access patterns
http://localhost
http://127.0.0.1
http://169.254.169.254 // AWS metadata
http://[::1]
```

### A02:2025 - Security Misconfiguration

Moved up from #5 in 2021 due to increased prevalence.

**Debug/development settings in production:**
```
DEBUG = True
app.debug = True
FLASK_DEBUG=1
NODE_ENV !== 'production' // Used incorrectly
devtool: 'source-map' // In production webpack
```

**Verbose error messages:**
```
console.error(error.stack)
res.send(error.message)
traceback.print_exc()
e.printStackTrace()
```

**Permissive CORS:**
```
Access-Control-Allow-Origin: *
cors({ origin: '*' })
@CrossOrigin(origins = "*")
```

**Missing security headers:**
- X-Content-Type-Options
- X-Frame-Options
- Content-Security-Policy
- Strict-Transport-Security

**Default credentials:**
```
username: 'admin', password: 'admin'
root:root
test:test123
```

### A03:2025 - Software Supply Chain Failures

NEW category - expanded from "Vulnerable and Outdated Components" to cover the entire software supply chain.

**Dependency vulnerabilities:**
- Outdated dependencies in package.json, requirements.txt, pom.xml, Gemfile
- Known vulnerable package versions
- Deprecated or unmaintained libraries
- Missing dependency lock files (package-lock.json, Pipfile.lock, etc.)

**Build pipeline risks:**
```
# Downloading without verification
curl | bash
curl | sh
wget && sh
pip install --trusted-host

# Unsigned packages
npm install // From untrusted registry
pip install --index-url http://

# Missing integrity checks
<script src="https://cdn.example.com/lib.js"> // No SRI hash
```

**CI/CD security:**
- Secrets exposed in CI logs
- Untrusted GitHub Actions or plugins
- Missing code signing
- Insecure artifact storage

**Detection approach:**
```
npm audit
pip-audit
bundle audit
mvn dependency:analyze
snyk test
```

### A04:2025 - Cryptographic Failures

**Weak cryptography:**
- MD5, SHA1 for passwords or sensitive data
- Hardcoded encryption keys/secrets
- Weak random number generation
- Missing encryption for sensitive data

**Detection patterns:**
```
# Weak hashing
md5(password)
SHA1.Create()
hashlib.md5()
MessageDigest.getInstance("MD5")
bcrypt.hashSync(password, 5) // Cost factor too low

# Hardcoded secrets
password = "hardcoded"
apiKey = "sk-..."
secret_key = "..."
private_key = "-----BEGIN"
AWS_SECRET_ACCESS_KEY = "..."

# Weak random
Math.random() // For security purposes
new Random() // Java - not SecureRandom
rand() // C - not cryptographically secure

# Deprecated TLS
SSLv3
TLSv1.0
TLSv1.1
```

### A05:2025 - Injection

Covers SQL, Command, XSS, LDAP, NoSQL, and other injection types.

**SQL Injection:**
```
"SELECT * FROM users WHERE id = " + userId
`SELECT * FROM users WHERE name = '${name}'`
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
f"SELECT * FROM users WHERE id = {user_id}"
```

**Command Injection:**
```
exec(userInput)
eval(userInput)
os.system(user_input)
subprocess.call(user_input, shell=True)
Runtime.getRuntime().exec(userInput)
child_process.exec(userInput)
```

**XSS (Cross-Site Scripting):**
```
innerHTML = userInput
document.write(userInput)
dangerouslySetInnerHTML={{ __html: userInput }}
<%- userInput %> // EJS unescaped
| safe // Jinja2 filter
{!! $userInput !!} // Laravel Blade unescaped
v-html="userInput" // Vue.js
```

**NoSQL Injection:**
```
User.find({ username: req.body.username })
db.collection.find({ $where: userInput })
```

**Template Injection:**
```
render_template_string(user_input)
Template(user_input)
```

### A06:2025 - Insecure Design

Look for these architectural issues:

- Missing rate limiting on authentication endpoints
- No account lockout after failed attempts
- Missing CAPTCHA on sensitive forms
- Lack of input validation schemas
- Missing business logic validation

**Detection patterns:**
```
# Missing rate limiting
app.post('/login', // No rate limiter middleware

# Weak password requirements
password.length >= 4
minLength: 6 // Should be at least 12
```

### A07:2025 - Authentication Failures

**Weak session management:**
```
# Session fixation
req.session.regenerate // Missing after login

# Insecure cookies
cookie: { secure: false }
httpOnly: false
sameSite: 'none'
```

**Credential exposure:**
```
console.log(password)
logger.info("Password: " + password)
print(f"User {username} with password {password}")
```

**Weak authentication:**
```
# No password hashing
User.create({ password: req.body.password })

# Timing attacks
if password == stored_password // Direct comparison
password.equals(storedPassword) // Not constant-time
```

### A08:2025 - Software or Data Integrity Failures

**Insecure deserialization:**
```
pickle.loads(user_data)
yaml.load(user_input) // Without Loader=SafeLoader
ObjectInputStream.readObject()
unserialize($user_input) // PHP
Marshal.load(user_input) // Ruby
```

**Missing integrity checks:**
```
curl | bash
wget && sh
<script src="https://cdn.example.com/lib.js"> // No SRI
```

### A09:2025 - Security Logging and Alerting Failures

Updated to emphasize alerting alongside logging.

- Missing authentication event logging
- No logging of access control failures
- Missing audit trails for sensitive operations
- No alerting mechanisms for security events

**Detection patterns:**
```
# Sensitive data in logs (violation)
logger.info("Credit card: " + cardNumber)
console.log(JSON.stringify(user)) // May include password
```

### A10:2025 - Mishandling of Exceptional Conditions

NEW category addressing poor error and exception handling.

**Failing open:**
```
try {
  authenticate(user)
} catch (e) {
  return true // Fails open!
}
```

**Incomplete error recovery:**
```
try { ... } catch (e) { } // Empty catch block
except Exception: pass // Python silent fail
```

**Resource exhaustion:**
```
fetch(url) // No timeout
requests.get(url) // No timeout parameter
while (true) { } // Infinite loop risk
Array(userInput) // Unbounded allocation
```

**ReDoS patterns:**
```
/(a+)+$/
/([a-zA-Z]+)*$/
```

## Output Format

Present findings as a security report:

```markdown
## Security Scan Results

### Summary
- Critical: X issues
- High: X issues
- Medium: X issues
- Low: X issues

### Critical Issues

#### [A05] SQL Injection in user authentication
- **File**: src/auth/login.js:45
- **Code**: `db.query("SELECT * FROM users WHERE id = " + userId)`
- **Risk**: Attackers can extract or modify database contents
- **Fix**: Use parameterized queries
```

## Language-Specific Patterns

### JavaScript/TypeScript
- `eval()`, `new Function()`
- `dangerouslySetInnerHTML`
- `child_process.exec` with user input
- Prototype pollution patterns

### Python
- `eval()`, `exec()`, `compile()`
- `pickle.loads()` with untrusted data
- `subprocess.call(..., shell=True)`
- `yaml.load()` without SafeLoader

### Java
- `Runtime.exec()` with user input
- `ObjectInputStream.readObject()`
- `Statement` vs `PreparedStatement`
- JNDI injection patterns

### PHP
- `eval()`, `system()`, `exec()`
- `unserialize()` with user data
- `include($user_input)`

### Go
- `os/exec.Command` with user input
- `html/template` vs `text/template`
- SQL injection with `fmt.Sprintf`

### Ruby
- `eval()`, `send()` with user input
- `system()`, backticks with user data
- `Marshal.load()` with user input

## Invocation

The user can invoke this skill with:
- `/owasp10` - Full OWASP Top 10 scan
- `/owasp10 A03` - Scan for specific category (e.g., Supply Chain)
- `/owasp10 --path src/` - Scan specific directory
