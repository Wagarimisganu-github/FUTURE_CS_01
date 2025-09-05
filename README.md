# Task o1 Web application security Testing, Vulnerability Assessment.


This report presents the findings from a web application vulnerability
assessment conducted on OWASP Juice Shop. The primary objective was to
identify common security flaws, analyze their potential impact, and
recommend remediation strategies. The vulnerabilities discovered during
testing include SQL Injection, Authentication Flaws, and potential
Cross-Site Scripting (XSS). These map directly to the OWASP Top 10
categories and represent real-world risks such as unauthorized access,
data leakage, and malicious script execution.

Implementing the suggested mitigations---such as parameterized queries,
enforcing strong authentication controls, and applying Content Security
Policies---will significantly strengthen the security posture of the
application.


### Purpose

The purpose of this internship project was to perform an ethical hacking
assessment on a test web application (OWASP Juice Shop), simulating
real-world penetration testing engagements. The exercise aimed to
provide hands-on experience in identifying vulnerabilities aligned with
the OWASP Top 10 and documenting them in a professional security report.

### Scope

-   Target: OWASP Juice Shop (demo instance)
-   Tools: Web browser (manual testing), OWASP resources
-   Standards: OWASP Top 10 2021

------------------------------------------------------------------------

## 2. Environment Setup & Exploration

**Environment:** - Application deployed at:
https://demo.owasp-juice.shop - Accessed using a standard web browser -
Manual testing approach focusing on core web functions

**Exploration Activities:** - Login and authentication workflows - Input
fields (login form, search, comment forms) - Error messages and
responses to crafted payloads

------------------------------------------------------------------------

## 3. Vulnerability Findings

### 3.1 SQL Injection

-   **Description:** Injection attempt using `' OR 1=1—` in the login
    form.
-   **Outcome:** Successful login without valid credentials
    (authentication bypass).
-   **Impact:** Unauthorized access to user accounts.
-   **Mitigation:** Use parameterized queries, validate and sanitize
    inputs.

### 3.2 Cross-Site Scripting (XSS)

-   **Description:** Injected `<script>alert("XSS")</script>` into form
    input.
-   **Outcome:** Input was accepted but alert did not execute; indicates
    potential stored/reflected XSS filtered at frontend.
-   **Impact:** Possible risk of script execution if bypassed.
-   **Mitigation:** Sanitize inputs, encode outputs, enforce Content
    Security Policy (CSP).

### 3.3 Authentication Flaw (Weak Credentials)

-   **Description:** Login attempt with breached credentials
    (admin@juice-sh.op / admin123).
-   **Outcome:** Login succeeded with weak credentials.
-   **Impact:** Exploitable authentication weakness; risk of account
    takeover.
-   **Mitigation:** Enforce strong password policies, implement account
    lockout, enable MFA.

------------------------------------------------------------------------

## 4. Mapping to OWASP Top 10

  ---------------------------------------------------------------------------
  Vulnerability    OWASP Top 10 Category Description              Status
  ---------------- --------------------- ------------------------ -----------
  SQL Injection    A03:2021 -- Injection Login bypass via crafted Confirmed
                                         SQL payload              

  Cross-Site       A07:2021 --           Input accepted,          Potential /
  Scripting        Identification &      potential for XSS        Observed
                   Authn. Failures\*                              

  Authentication   A07:2021 --           Weak credentials         Confirmed
  Flaw             Identification &      accepted                 
                   Authentication                                 
                   Failures                                       
  ---------------------------------------------------------------------------

## 5. Impact Analysis & Risk Rating

  ------------------------------------------------------------------------------
  Vulnerability          Impact Level Likelihood   Overall Risk Description
  ---------------------- ------------ ------------ ------------ ----------------
  SQL Injection          Critical     High         High         Full
                                                                authentication
                                                                bypass possible

  Cross-Site Scripting   Medium       Medium       Medium       Malicious script
                                                                execution
                                                                possible if
                                                                filters bypassed

  Authentication Flaw    High         High         High         Weak/default
                                                                credentials
                                                                enable
                                                                unauthorized
                                                                access
  ------------------------------------------------------------------------------

------------------------------------------------------------------------

## 6. Remediation & Recommendations

  ------------------------------------------------------------------------------
  Vulnerability    Recommended Fixes                                  Priority
  ---------------- -------------------------------------------------- ----------
  SQL Injection    Implement prepared statements; strict input        High
                   validation                                         

  Cross-Site       Sanitize inputs, encode outputs, implement CSP     Medium
  Scripting                                                           

  Authentication   Strong password policies, MFA, account lockout     High
  Flaw             after failed attempts                              
  ------------------------------------------------------------------------------

------------------------------------------------------------------------

## 7. Conclusion

The assessment of OWASP Juice Shop revealed several vulnerabilities that
align with OWASP Top 10 risks. The confirmed flaws (SQL Injection and
Authentication Weaknesses) pose serious threats to confidentiality and
integrity if left unresolved. Addressing these vulnerabilities promptly
will significantly reduce exposure to exploitation and enhance the
security of the application. The exercise provided practical experience
in vulnerability assessment and remediation planning.


## 9. Aknowledgments

-   Special thakns to ** Future Interns ** for this opportunity


**Author:** Waggari Misganu Ebsa\
** Meet me @ **
Email : wagarimisganu12@gmail.com
Linkedin: https://www.linkedin.com/in/waggari-misganu-ebsa-352601317/
