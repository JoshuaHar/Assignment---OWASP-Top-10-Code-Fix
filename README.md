# OWASP Top 10 Vulnerabilities – Code Samples and Fixes

## 1. Broken Access Control 1

**Flaw**
Any user can request any profile just by changing `:userId`. This is an Insecure Direct Object Reference (IDOR), allowing unauthorized access to sensitive data.

**Fix Explanation**
The fix enforces authorization checks, ensuring users can only access their own profile unless they are admins. Sensitive fields are also excluded from the response.

**Reference**
[OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

## 2. Broken Access Control 2

**Flaw**
Any logged-in user can access another user’s account data by modifying the `user_id` in the URL.

**Fix Explanation**
The fix checks whether the authenticated user matches the requested account or has admin privileges. Unauthorized access attempts return HTTP 403.

**Reference**
[OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## 3. Cryptographic Failures 1

**Flaw**
MD5 is insecure and vulnerable to collisions and rainbow table attacks.

**Fix Explanation**
The fix uses bcrypt, a modern password hashing algorithm with built-in salt and adaptive cost factor. This makes brute-force and rainbow table attacks impractical.

**Reference**
[OWASP A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

## 4. Cryptographic Failures 2

**Flaw**
SHA-1 is deprecated and insecure against collision attacks.

**Fix Explanation**
The fix uses bcrypt from Passlib, providing secure hashing with salt and configurable cost factor.

**Reference**
[OWASP A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

## 5. Injection 1

**Flaw**
Concatenating user input into SQL queries makes this code vulnerable to SQL Injection.

**Fix Explanation**
The fix uses parameterized queries (`PreparedStatement`), ensuring user input is properly escaped and preventing injection attacks.

**Reference**
[OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

---

## 6. Injection 2

**Flaw**
Directly trusting query parameters can allow attackers to inject NoSQL operators (e.g., `{"$ne": null}`) to bypass authentication.

**Fix Explanation**
The fix validates input, ensuring only safe characters are accepted. MongoDB queries are strictly structured to avoid `$`-operator injection.

**Reference**
[OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

---

## 7. Insecure Design

**Flaw**
The design is insecure: anyone knowing an email can reset the password without verification.

**Fix Explanation**
The fix introduces a secure reset token with expiration, sent to the user’s email, ensuring only the account owner can reset the password.

**Reference**
[OWASP A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

---

## 8. Software and Data Integrity Failures

**Flaw**
The external script could be tampered with, leading to supply chain attacks.

**Fix Explanation**
The fix adds a Subresource Integrity (SRI) attribute, ensuring the browser verifies the script’s cryptographic hash before execution.

**Reference**
[OWASP A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

---

## 9. Server-Side Request Forgery

**Flaw**
Attackers can trick the server into making requests to internal services (e.g., AWS metadata).

**Fix Explanation**
The fix validates the destination host against an allowlist and enforces timeouts to mitigate SSRF risks.

**Reference**
[OWASP A10:2021 – Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

---

## 10. Identification and Authentication Failures

**Flaw**
Passwords are stored in plaintext and compared directly, making them easily compromised if the database leaks.

**Fix Explanation**
The fix ensures passwords are stored as bcrypt hashes and validated securely. Plaintext storage and comparison are eliminated.

**Reference**
[OWASP A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

## Requirements

- Flask
- SQLAlchemy
- Werkzeug
- Passlib [bcrypt]
- bcrypt
- requests
- pymongo
- Node.js / Express
- Mongoose
- Java JDK
- JDBC driver
