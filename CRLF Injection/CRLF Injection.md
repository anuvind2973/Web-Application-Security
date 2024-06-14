# CRLF Injection

<p align="justify">CRLF (Carriage Return Line Feed) injection is a web application vulnerability that occurs when an attacker can inject malicious CRLF characters into an HTTP response. This vulnerability can lead to various security issues, such as HTTP header injection, HTTP response splitting, session fixation, cross-site scripting (XSS), and cache poisoning.</p>

### Understanding the CRLF Injection
To understand CRLF injection, let’s break down the term:

* Carriage Return (CR): It is a control character (ASCII code 13) that instructs the cursor to return to the beginning of the current line.
* Line Feed (LF): It is a control character (ASCII code 10) that instructs the cursor to move to the next line.

<p align="justify"> In the context of HTTP, CRLF refers to the sequence of both CR and LF characters (“\r\n”). These characters are used to separate lines in the HTTP protocol.</p>

<p align="justify"> The CRLF injection vulnerability arises when user-controlled data (input) is not properly sanitized or validated before being used in constructing an HTTP response. Attackers exploit this vulnerability by injecting CRLF characters into user input to manipulate the HTTP response.</p>

### Discovery

To find a CRLF vulnerability, you want to logically think about where in the web application user input would be:

* Reflected as a header (cookies, redirects)
* Included in a file (logs)
* Included in a server-side request (email, server-side HTTP request)
* To include a CRLF in a URL parameter, use these URL-encoded values:

<b> Carriage return: %0d </b>

<b> Line feed: %0a </b>
