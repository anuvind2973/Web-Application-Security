
# Server-Side Template Injection (SSTI)

Server-side template Injection (SSTI) is a vulnerability that occurs when an application allows an attacker to inject malicious code into a server-side template. This can lead to the execution of arbitrary code on the server, potentially resulting in data theft, unauthorized access, or other security risks.

In other words, Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is
extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to
directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable
application into a potential pivot point.


Template Injection can arise both through developer error and the intentional exposure of templates in an attempt
to offer rich functionality, as commonly done by wikis, blogs, marketing applications, and content management systems.
Intentional template injection is such a common use case that many template engines offer a 'sandboxed' mode for this
express purpose. This paper defines a methodology for detecting and exploiting template injection and shows it being
applied to craft RCE zero-days for two widely deployed enterprise web applications. Generic exploits are demonstrated for
five of the most popular template engines, including escapes from sandboxes whose entire purpose is to handle user-supplied templates safely.

### Detect Injection
These chars can be used one by one to check if it is vulnerable until we either get an error, or some characters start disappearing from the output. ${{<%[%'"}}%

### Identify Template Engine

![Alt text](https://github.com/anuvind2973/Web-Application-Security/blob/main/Server%20Side%20Template%20Injection/Identify%20Template%20Engine.png)

