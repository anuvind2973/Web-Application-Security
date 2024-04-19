
# Server-Side Template Injection (SSTI)

<p align="justify">Server-side template Injection (SSTI) is a vulnerability that occurs when an application allows an attacker to inject malicious code into a server-side template. This can lead to the execution of arbitrary code on the server, potentially resulting in data theft, unauthorized access, or other security risks.</p>

In other words, Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is
extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to
directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable
application into a potential pivot point.

Template Injection can arise both through developer error and the intentional exposure of templates in an attempt
to offer rich functionality, as commonly done by wikis, blogs, marketing applications, and content management systems.
Intentional template injection is such a common use case that many template engines offer a 'sandboxed' mode for this
express purpose. This paper defines a methodology for detecting and exploiting template injection and shows it being
applied to craft RCE zero-days for two widely deployed enterprise web applications. Generic exploits are demonstrated for
five of the most popular template engines, including Escapes from Sandboxes whose entire purpose is to handle user-supplied templates safely.
#### Let’s look at the following list of some of the most well-known template engines:
* PHP: Smarty, Twigs
* Java: Velocity, Freemaker
* Python: Jinja, Mako, Tornado
* JavaScript: – Jade, Rage
* Ruby: Liquid


### Detect Injection
For our enumeration phase, we will follow the below steps to identify the vulnerability:
* Identify the application’s built-in language and the running template engine.
* Identify injectable user-controlled inputs in GET and POST requests.
* Fuzz the application with special characters ${{<%[%'"}}%\. Observe which ones get interpreted by the server and which ones raise errors.
* Insert basic template injection payloads in all user inputs, and observe if the application engine evaluates them.

### Identify Template Engine

![Alt text](https://github.com/anuvind2973/Web-Application-Security/blob/main/Server%20Side%20Template%20Injection/Identify%20Template%20Engine.png)

