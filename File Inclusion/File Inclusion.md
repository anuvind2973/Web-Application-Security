
# File Inclusion

<p align="justify">HTTP parameters to specify what is shown on the web page, which allows for building dynamic web pages, reduces the script's overall size, and simplifies the code. In such cases, parameters are used to specify which resource is shown on the page. If such functionalities are not securely coded, an attacker may manipulate these parameters to display the content of any local file on the hosting server, leading to a Local File Inclusion (LFI) vulnerability.</p>

### Local File Inclusion (LFI)

<p align="justify">Local File Inclusion (LFI) allows an attacker to include files on a server through the web browser. This vulnerability exists when a web application includes a file without correctly sanitizing the input, allowing and attacker to manipulate the input and inject path traversal characters, and include other files from the web server.</p>

<p align="justify">LFI vulnerabilities can lead to source code disclosure, sensitive data exposure, and even remote code execution under certain conditions. Leaking source code may allow attackers to test the code for other vulnerabilities, which may reveal previously unknown vulnerabilities. Furthermore, leaking sensitive data may enable attackers to enumerate the remote server for other weaknesses or even leak credentials and keys that may allow them to access the remote server directly. Under specific conditions, LFI may also allow attackers to execute code on the remote server, which may compromise the entire back-end server and any other servers connected to it.</p>

#### Examples of Vulnerable Code
<p align="justify">Let's look at some examples of code vulnerable to File Inclusion to understand how such vulnerabilities occur.</p>

PHP LFI vulnerable code

```
<?php
$file = $_GET['file']; // Vulnerable input

// Include the file based on user input
include($file . '.php');
?>
```
<p align="justify">In this code, the $file variable is directly taken from the user input via the $_GET superglobal without any validation or sanitization. An attacker can exploit this vulnerability by manipulating the file parameter in the URL to include arbitrary files from the server's filesystem.</p>


### Path traversal

<p align="justify">Path traversal is also known as directory traversal. These vulnerabilities enable an attacker to read arbitrary files on the server that is running an application. This might include:</p>

* Application code and data.
* Credentials for back-end systems.
*Sensitive operating system files.

<p align="justify">In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.</p>

### Basic Bypasses

#### Non-Recursive Path Traversal Filters

``` $language = str_replace('../', '', $_GET['language']); ```

``` http://example.com/index.php?language=../../../etc/passwd ```

<p align="justify">One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (../) to avoid path traversals. 
../ substrings were removed, which resulted in a final path being ./languages/etc/passwd. </p>

<p align="justify">However, this filter is very insecure, as it is not recursively removing the ../ substring, as it runs a single time on the input string and does not apply the filter on the output string. For example, if we use ....// as our payload, then the filter would remove ../ and the output string would be ../, which means we may still perform path traversal. Let's try applying this logic to include /etc/passwd again:</p>

``` http://example.com/index.php?language=....//....//....//etc/passwd ```

<p align="justify">The ....// substring is not the only bypass we can use, as we may use ..././ or ....\/ and several other recursive LFI payloads. Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g. ....\/), or adding extra forward slashes (e.g. ....////)</p>

### Encoding

<p align="justify">Some web filters may prevent input filters that include certain LFI-related characters, like a dot . or a slash / used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function</p>

<p align="justify">If the target web application did not allow. and / in our input, we can URL encode ../ into %2e%2e%2f, which may bypass the filter.</p>

<p align="justify">Furthermore, we may also use Burp Decoder to encode the encoded string once again to have a double-encoded string, which may also bypass other types of filters.</p>

### Appended Extension

<p align="justify">As discussed in the previous section, some web applications append an extension to our input string (e.g. .php), to ensure that the file we include is in the expected extension. With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension</p>

### Path Truncation

<p align="justify">In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be truncated, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (/etc/passwd/.) then the /. would also be truncated, and PHP would call (/etc/passwd). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. ////etc/passwd is the same as /etc/passwd). Similarly, a current directory shortcut (.) in the middle of the path would also be disregarded (e.g. /etc/./passwd).</p>


<p align="justify">If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (.php) would be truncated, and we would have a path without an appended extension. Finally, it is also important to note that we would also need to start the path with a non-existing directory for this technique to work.</p>


An example of such payload would be the following:

```
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```
Of course, we don't have to manually type ./ 2048 times (total of 4096 characters), but we can automate the creation of this string with the following command:

```
[!bash!]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```
non_existing_directory ``` /../../../etc/passwd/./././<SNIP>././././ ```

<p align="justify">We may also increase the count of ../, as adding more would still land us in the root directory, as explained in the previous section. However, if we use this method, we should calculate the full length of the string to ensure only .php gets truncated and not our requested file at the end of the string (/etc/passwd). This is why it would be easier to use the first method.</p>

### Null Bytes

<p align="justify">PHP versions before 5.5 were vulnerable to null byte injection, which means that adding a null byte (%00) at the end of the string would terminate the string and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string, as seen in Assembly, C, or C++ languages.</p>

<p align="justify">To exploit this vulnerability, we can end our payload with a null byte (e.g. /etc/passwd%00), such that the final path passed to include() would be (/etc/passwd%00.php). This way, even though .php is appended to our string, anything after the null byte would be truncated, and so the path used would actually be /etc/passwd, leading us to bypass the appended extension.</p>

### PHP Filters

<p align="justify">Many popular web applications are developed in PHP, along with various custom web applications built with different PHP frameworks, like Laravel or Symfony. If we identify an LFI vulnerability in PHP web applications, then we can utilize different PHP Wrappers to be able to extend our LFI exploitation, and even potentially reach remote code execution.</p>

<p align="justify">PHP Wrappers allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams. This has a lot of uses for PHP developers. Still, as web penetration testers, we can utilize these wrappers to extend our exploitation attacks and be able to read PHP source code files or even execute system commands. This is not only beneficial with LFI attacks, but also with other web attacks like XXE, as covered in the Web Attacks module.</p>

<p align="justify">In this section, we will see how basic PHP filters are used to read PHP source code, and in the next section, we will see how different PHP wrappers can help us in gaining remote code execution through LFI vulnerabilities.</p>

#### Input Filters

<p align="justify">PHP Filters are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the php:// scheme in our string, and we can access the PHP filter wrapper with ``` php://filter/ ```.</p>

<p align="justify">The filter wrapper has several parameters, but the main ones we require for our attack are resource and read. The resource parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the read parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.</p>

<p align="justify">There are four different types of filters available for use, which are String Filters, Conversion Filters, Compression Filters, and Encryption Filters. You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the convert.base64-encode filter, under Conversion Filters.

#### Fuzzing for PHP Files

<p align="justify">The first step would be to fuzz for different available PHP pages with a tool like ffuf or gobuster, as covered in the Attacking Web Applications with Ffuf module:

 ##### PHP Filters
 
```` ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php ````


<p align="justify">Tip: Unlike normal web application usage, we are not restricted to pages with HTTP response code 200, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.</p>

<p align="justify">Even after reading the sources of any identified files, we can scan them for other referenced PHP files, and then read those as well, until we are able to capture most of the web application's source or have an accurate image of what it does. It is also possible to start by reading index.php and scanning it for more references and so on, but fuzzing for PHP files may reveal some files that may not otherwise be found that way.</p>








https://academy.hackthebox.com/module/23/section/1492
https://academy.hackthebox.com/module/23/section/1491
https://www.google.com/search?q=javascript+lfi+vulnerability+code&sca_esv=125395e02bc1fefe&sca_upv=1&rlz=1C1VDKB_enIN1066IN1066&sxsrf=ACQVn09LDgIbAe0fetF7wuSZW9ELXgwbVQ%3A1713508799071&ei=vxEiZsHyA__hseMPmZq_wAc&ved=0ahUKEwiBzqba1c2FAxX_cGwGHRnND3gQ4dUDCBE&oq=javascript+lfi+vulnerability+code&gs_lp=Egxnd3Mtd2l6LXNlcnAiIWphdmFzY3JpcHQgbGZpIHZ1bG5lcmFiaWxpdHkgY29kZTIIEAAYgAQYogQyCBAAGIAEGKIEMggQABiABBiiBEjnCVAAWABwAHgBkAEAmAGIAaABiAGqAQMwLjG4AQzIAQD4AQL4AQGYAgGgAowBmAMAkgcDMC4xoAefAg&sclient=gws-wiz-serp
https://www.vaadata.com/blog/exploiting-an-lfi-local-file-inclusion-vulnerability-and-security-tips/
https://skf.gitbook.io/asvs-write-ups/local-file-inclusion-1-lfi-1/lfi-1
https://github.com/Security-Knowledge-Framework/Labs
https://skf.gitbook.io/asvs-write-ups
https://owasp.org/www-community/attacks/Path_Traversal
https://skf.gitbook.io/asvs-write-ups/local-file-inclusion-3-lfi-3/lfi-3-1
https://gupta-bless.medium.com/exploiting-local-file-inclusion-lfi-using-php-wrapper-89904478b225
https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb
https://www.google.com/search?q=lfi+hack+the+box&rlz=1C1VDKB_enIN1066IN1066&oq=LFI+hackthe+&gs_lcrp=EgZjaHJvbWUqCAgBEAAYDRgeMgYIABBFGDkyCAgBEAAYDRgeMg0IAhAAGIYDGIAEGIoFMg0IAxAAGIYDGIAEGIoF0gEINTEzOGowajeoAgCwAgA&sourceid=chrome&ie=UTF-8
https://medium.com/hackthebox-writeups-by-jsinix/hack-the-box-beep-1293837d2293
https://medium.com/@harry.hphu/hackthebox-file-inclusion-local-file-inclusion-lfi-1a8a83878153
https://www.google.com/search?q=Second+Order+Attack+LFI&rlz=1C1VDKB_enIN1066IN1066&oq=Second+Order+Attack+LFI&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIHCAEQIRigATIHCAIQIRigAdIBCDIwNDBqMGo3qAIAsAIA&sourceid=chrome&ie=UTF-8
https://www.google.com/search?q=Approved+Paths+LFI&sca_esv=09379ecd0b6efd91&sca_upv=1&rlz=1C1VDKB_enIN1066IN1066&sxsrf=ACQVn0_bv6nzr3RhYTpBR3rV7ocsH7wXjQ%3A1713551020383&ei=rLYiZtaFF726vr0P96-XoAs&ved=0ahUKEwjWi__-8s6FAxU9na8BHffXBbQQ4dUDCBE&uact=5&oq=Approved+Paths+LFI&gs_lp=Egxnd3Mtd2l6LXNlcnAiEkFwcHJvdmVkIFBhdGhzIExGSTIFECEYoAEyBRAhGKABSLoTUHNYrhBwAXgBkAEAmAG0AaABmAWqAQMwLjS4AQPIAQD4AQGYAgWgAqQFwgIKEAAYsAMY1gQYR8ICBhAAGBYYHsICCxAAGIAEGIYDGIoFwgIHECEYoAEYCpgDAIgGAZAGBJIHAzEuNKAHyws&sclient=gws-wiz-serp
https://book.hacktricks.xyz/pentesting-web/file-inclusion
https://0xffsec.com/handbook/web-applications/file-inclusion-and-path-traversal/
https://chromewebstore.google.com/detail/copy-all-urls/djdmadneanknadilpjiknlnanaolmbfk


https://www.google.com/search?q=Local+File+Inclusion+(LFI)+blogs&rlz=1C1VDKB_enIN1066IN1066&oq=Local+File+Inclusion+(LFI)+blogs&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIJCAEQIRgKGKABMgkIAhAhGAoYoAHSAQg0ODUxajBqN6gCALACAA&sourceid=chrome&ie=UTF-8#ip=1
https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/#:~:text=Frequently%20asked%20questions-,What%20is%20local%20file%20inclusion%20(LFI)%3F,this%20website%20or%20web%20application.
https://brightsec.com/blog/local-file-inclusion-lfi/
https://www.vaadata.com/blog/exploiting-an-lfi-local-file-inclusion-vulnerability-and-security-tips/
https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/
https://snapsec.co/blog/LFI/
https://medium.com/@tanmay_deshpande/local-file-inclusion-lfi-attack-46485f294aef
https://www.hackingarticles.in/comprehensive-guide-to-local-file-inclusion/
https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html
https://touhidshaikh.com/blog/2023/01/local-file-inclusionlfi-explained/
https://systemweakness.com/local-file-inclusion-lfi-a-beginners-guide-5629bbcbcffb
https://medium.com/@anekantsinghai/best-approach-to-lfi-40c91f1dfc54
https://tcm-sec.com/local-file-inclusion-a-practical-guide/
https://hacklido.com/blog/190-local-file-inclusion-lfi-cheatsheet
https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1/
https://www.linkedin.com/pulse/file-inclusion-vulnerabilities-dinesh-reddy-challa
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md
https://notchxor.github.io/oscp-notes/2-web/LFI-RFI/
https://notes.defendergb.org/web-sec/vuln/lfi-rfi
https://github.com/xmendez/wfuzz/blob/master/wordlist/vulns/dirTraversal-nix.txt
https://book.hacktricks.xyz/pentesting-web/file-inclusion
https://hackerone.com/reports/39428
https://github.com/rezaJOY/Local-File-Inclusion-Payloads
https://thehackernews.com/search/label/Local%20file%20inclusion
https://blog.cyscomvit.com/2021/07/local-file-inclusion.html










