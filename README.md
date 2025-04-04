# Multi-LLM Judge SAST System - Vulnerability Assessment Results

This repository showcases the capabilities and results of our advanced Static Application Security Testing (SAST) system that leverages a multi-LLM judge architecture to identify and assess vulnerabilities in popular deliberately vulnerable web applications.

Please note the PoC capabilities was limited to:

- $2 USD per repo scan (which limit the token usage for all three models) to prevent the model to hallucinate / trapped in loophole
- The system prompts provided to the Claude Code explicitly command the model to find the top 10 most risky issues and spent most of token to dynamically perform trace/track analysis

Any increase in these 2 conditions would lead to better context window and is expected to perform better in providing more stable, thoughtful and deeper result.

## 🔍 System Architecture

Detailed explaination on Architecture and PoC: https://jo14.medium.com/beyond-sast-building-a-multi-llm-judge-for-context-aware-security-analysis-86f6783e661d

Our SAST system implements a novel approach that combines multiple Large Language Models in a judge architecture:


### Core Components:

1. **Code Analysis Pipeline**
   - Repository analysis via Claude Code
   - Context-aware prompt generation with Claude API
   - Dynamic analysis with MVC pattern recognition
   - Initial vulnerability identification

2. **Multi-LLM Judge System**
   - Independent assessment by DeepSeek (r1) and OpenAI (o1) models
   - Cross-model reasoning dialogue
   - Impartial synthesis by Claude API to eliminate biases

3. **Evaluation & Integration**
   - Final vulnerability confirmation
   - False positive elimination
   - Security ticket generation
   - JIRA and DefectDojo integration

## 📊 Applications Under Test

Our system is designed to scan a variety of deliberately vulnerable applications to demonstrate effectiveness across different tech stacks, vulnerability types, and application architectures.

| Application | Tech Stack | Status | Date Scanned |
|-------------|------------|--------|--------------|
| [OWASP NodeGoat](#owasp-nodegoat) | Node.js, Express, MongoDB | ✅ Complete | April 2, 2025 |
| [OWASP Juice Shop](#owasp-juice-shop) | Node.js, Angular, REST API | ✅ Complete | April 5, 2025 |
| DVWA | PHP, MySQL |  | - |
| WebGoat | Java, Spring | | - |
| OWASP Mutillidae II | PHP, MySQL |  | - |
| RailsGoat | Ruby on Rails |  | - |

## 🔐 OWASP NodeGoat

OWASP NodeGoat is a deliberately vulnerable Node.js application designed to showcase the OWASP Top 10 vulnerabilities in a modern JavaScript environment.

### Summary of Findings

| Severity | Count | Description |
|----------|-------|-------------|
| P0 (Critical) | 2 | Server-Side JavaScript Injection, NoSQL Injection |
| P1 (High) | 6 | SSRF, ReDoS, IDOR, Plaintext Passwords, Stored XSS, Session Management Weaknesses |
| P2 (Medium) | 3 | CSRF Protection, Prototype Pollution, Context Confusion XSS |
| P3 (Low) | 0 | - |
| **Total** | **11** | |

### Detailed Vulnerability Report

| ID | Vulnerability | Location | Severity | CWE | 
|----|--------------|----------|----------|-----|
| SECVULN-001 | Server-Side JavaScript Injection via eval() | /app/routes/contributions.js (32-34) | P0 (Critical) | CWE-94 |
| SECVULN-002 | NoSQL Injection with JavaScript Execution | /app/data/allocations-dao.js (77-79) | P0 (Critical) | CWE-943 |
| SECVULN-003 | Server-Side Request Forgery (SSRF) | /app/routes/research.js (15-16) | P1 (High) | CWE-918 |
| SECVULN-004 | Regular Expression Denial of Service (ReDoS) | /app/routes/profile.js (59) | P1 (High) | CWE-1333 |
| SECVULN-005 | Insecure Direct Object Reference (IDOR) | /app/routes/allocations.js (16-19) | P1 (High) | CWE-639 |
| SECVULN-006 | Plaintext Password Storage and Comparison | /app/data/user-dao.js (25-30, 60-67) | P1 (High) | CWE-521 |
| SECVULN-007 | Stored XSS in Memos | /app/routes/memos.js, /app/data/memos-dao.js | P1 (High) | CWE-79 |
| SECVULN-008 | Missing CSRF Protection | /server.js (104-113) | P2 (Medium) | CWE-352 |
| SECVULN-009 | Prototype Pollution Vulnerability | /app/routes/profile.js (33-36, 100-103) | P2 (Medium) | CWE-1321 |
| SECVULN-010 | XSS via Context Confusion | /app/routes/profile.js (28) | P2 (Medium) | CWE-79 |
| SECVULN-011 | Session Management Weaknesses | /app/routes/session.js (116-117), /server.js (78-102) | P1 (High) | CWE-384 |

For detailed analysis of each vulnerability, including attack vectors, exploitation evidence, and remediation guidance, see our [NodeGoat Detailed Analysis](./analysis/nodegoat-detailed.md).

## 🛒 OWASP Juice Shop

OWASP Juice Shop is a modern deliberately vulnerable web application written in Node.js, Express, and Angular. It features a rich set of security vulnerabilities across the full stack.

### Summary of Findings

| Severity | Count | Description |
|----------|-------|-------------|
| P0 (Critical) | 3 | SQL Injection, JWT Algorithm Confusion, Hardcoded JWT Private Key |
| P1 (High) | 4 | Cross-Site Scripting, Unrestricted File Upload, XXE Injection, Insecure Deserialization |
| P2 (Medium) | 1 | Open Redirect |
| P3 (Low) | 0 | - |
| **Total** | **8** | |

### Detailed Vulnerability Report

| ID | Vulnerability | Location | Severity | CWE | 
|----|--------------|----------|----------|-----|
| SECVULN-001 | SQL Injection in Authentication | routes/login.ts (36) | P0 (Critical) | CWE-89 |
| SECVULN-002 | JWT Algorithm Confusion Attack | routes/verify.ts (84-90), lib/insecurity.ts (54-58) | P0 (Critical) | CWE-347 |
| SECVULN-003 | Cross-Site Scripting via Angular Sanitization Bypass | frontend/src/app/search-result/search-result.component.ts (160) | P1 (High) | CWE-79 |
| SECVULN-004 | Unrestricted File Upload Leading to Path Traversal | routes/fileUpload.ts (39-47) | P1 (High) | CWE-22 |
| SECVULN-005 | XML External Entity (XXE) Injection | routes/fileUpload.ts (75-106) | P1 (High) | CWE-611 |
| SECVULN-006 | Open Redirect Vulnerability | lib/insecurity.ts (135-141) | P2 (Medium) | CWE-601 |
| SECVULN-007 | Hardcoded JWT Private Key | lib/insecurity.ts (23) | P0 (Critical) | CWE-798 |
| SECVULN-008 | Insecure Deserialization in YAML Processing | routes/fileUpload.ts (108-137) | P1 (High) | CWE-502 |

For detailed analysis of each vulnerability, including attack vectors, exploitation evidence, and remediation guidance, see our [Juice Shop Detailed Analysis](./analysis/juiceshop-detailed.md).

## 🔍 Cross-Application Analysis

Our scanning across multiple applications reveals interesting patterns in vulnerability types and severity:

| Vulnerability Category | NodeGoat | Juice Shop | Notes |
|------------------------|----------|------------|-------|
| Injection Flaws | 2 | 3 | Both applications vulnerable to different injection types |
| Authentication Weaknesses | 2 | 2 | JWT issues prevalent in modern apps |
| XSS Vulnerabilities | 2 | 1 | NodeGoat more prone to traditional XSS |
| File-related Vulnerabilities | 0 | 3 | Juice Shop has more file handling issues |
| Security Misconfiguration | 5 | 2 | Common across both applications |

