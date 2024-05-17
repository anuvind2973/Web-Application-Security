# Escalating PHP Deserialization

<p align="justify"> Don’t despair when you can’t RCE. How to achieve authentication bypass and SQL injection using PHP’s unserialize().</p>

<p align="justify"> Last time, we talked about how PHP’s unserialize leads to vulnerabilities, and how an attacker can utilize it to achieve RCE.</p>

<p align="justify"> Today, let’s discuss some of the different ways that an attacker can exploit an unserialize() vulnerability. Even if RCE is not possible, attackers can still use unserialize() vulnerabilities to achieve authentication bypass and SQL injection.</p>

#33 Authentication bypass

<p align="justify"> Besides RCE, unserialize() issues are often used to bypass authentication controls of an application. There are two ways to do this: by manipulating object properties that are used as access control, and by utilizing type juggling issues to trick an application. Both methods rely on the fact that the end-user can control the object passed into unserialize().</p>

### Manipulating object properties to bypass authentication

<p align="justify"> One of the simplest and most common ways for an attacker to exploit a deserialization flaw is by manipulating object properties to bypass authentication.</p>

````
class User{
  public $username = "vickie";
  public $type = "Regular User";
  # some more PHP code
}
````
<p align="justify"> Let’s say the application utilized a class called User to communicate user info during the signup process. The user will fill out a form, and the information will be communicated to the backend through a serialized User object.</p>

<p align="justify"> Since the end-user controls the User object, she can simply manipulate the object like so, and register as an admin user.</p>

````
class User{
  public $username = "vickie";
  public $type = "Admin User";
  # some more PHP code
}
````
## PHP Type Juggling Vulnerabilities

<p align="justify"> How PHP’s type comparison features lead to vulnerabilities, and how to avoid them.

<p align="justify"> Much like Python and Javascript, PHP is a dynamically typed language. This means that variable types are checked while the program is executing. Dynamic typing allows developers to be more flexible when using PHP. But this kind of flexibility sometimes causes unexpected errors in the program flow and can even introduce critical vulnerabilities into the application.</p>

<p align="justify"> Today, let’s dive into PHP type juggling, and how they lead to authentication bypass vulnerabilities.</p>

## How PHP compares values

<p align="justify"> PHP has a feature called “type juggling”, or “type coercion”. This means that during the comparison of variables of different types, PHP will first convert them to a common, comparable type.</p> 

For example, when the program is comparing the string “7” and the integer 7 in the scenario below:
````
$example_int = 7;
$example_str = "7";

if ($example_int == $example_str) {
 echo("PHP can compare ints and strings.")
}
````
<p align="justify"> The code will run without errors and output “PHP can compare ints and strings.” This behavior is very helpful when you want your program to be flexible in dealing with different types of user input.</p>

<p align="justify"> However, it is also important to note that this behavior is also a major source of bugs and security vulnerabilities.</p>

<p align="justify">For example, when PHP needs to compare the string “7 puppies” to the integer 7, PHP will attempt to extract the integer from the string. So this comparison will evaluate to True.</p>
````
("7 puppies" == 7) -> True

````
 <p align="justify"> But what if the string that is being compared does not contain an integer? The string will then be converted to a “0”. So the following comparison will also evaluate to True:</p>
````
("Puppies" == 0) -> True
````
<p align="justify"> Loose type comparison behavior like these is pretty common in PHP and many built-in functions work in the same way. You can probably already see how this can be very problematic, but how exactly can hackers exploit this behavior? </p>

### How vulnerability arises

<p align="justify"> The most common way that this particularity in PHP is exploited is by using it to bypass authentication.</p>

<p align="justify"> Let’s say the PHP code that handles authentication looks like this:</p>

````

if ($_POST["password"] == "Admin_Password") {
	login_as_admin();
}

````

<p align="justify"> Then, simply submitting an integer input of 0 would successfully log you in as admin, since this will evaluate to True:</p>

````
(0 == "Admin_Password") -> True

````
### Conditions of exploitation

<p align="justify"> However, this vulnerability is not always exploitable and often needs to be combined with a deserialization flaw. The reason for this is that POST, GET parameters and cookie values are, for the most part, passed as strings or arrays into the program. </p>

<p align="justify"> If the POST parameter from the example above is passed into the program as a string, PHP would be comparing two strings, and no type conversion would be needed. And “0” and “Admin_Password” are, obviously, different strings.</p>
````
("0" == "Admin_Password") -> False
````
<p align="justify"> However, type juggling issues can be exploited if the application takes accepts the input via functions like json_decode() or unserialize(). This way, it would be possible for the end-user to specify the type of input passed in.</p>
````
{"password": "0"}
{"password": 0}
````
<p align="justify"> Consider the above JSON blobs. The first one would cause the password parameter to be treated as a string whereas the second one would cause the input to be interpreted as an integer by PHP. This gives an attacker fine-grained control of the input data type and therefore the ability to exploit type juggling issues.</p>

### Avoiding type juggling issues in PHP code

<p align="justify"> As a developer, there are several steps that you can take to prevent these vulnerabilities from happening.</p>

#### Use strict comparison operatorsPermalink

<p align="justify"> When comparing values, always try to use the type-safe comparison operator “===” instead of the loose comparison operator “==”. This will ensure that PHP does not type juggle and the operation will only return True if the types of the two variables also match. This means that (7 === “7”) will return False.</p>

#### Specify the “strict” option for functions that compare

<p align="justify"> Always consult the PHP manual on individual functions to check if they use loose comparison or type-safe comparison. See if there is an option to use strict comparison and specify that option in your code.</p>

<p align="justify"> For example, PHP’s in_array() uses loose comparison by default. But you can make it switch to type-safe comparison by specifying the strict option.</p>

<p align="justify"> If the function only provides loose comparison, avoid using that function and search for alternatives instead.</p>

#### Avoid typecasting before comparisonPermalink

<p align="justify"> Avoid typecasting right before comparing values, as this will essentially deliver the same results as type juggling. For example, before typecasting, the following three variables are all seen as distinct by the type-safe operator.</p>

````
$example_int = 7;
$example_str = "7_string";
$example_str_2 = "7";

if ($example_int === $example_str) {
  # This condition statement will return False
  echo("This will not print.");
}

if ($example_int === $example_str_2) {
  # This condition statement will return False
  echo("This will not print.");
}
````
<p align="justify"> Whereas after typecasting, PHP will only preserve the number extracted from a string, and “7_string” will become the integer 7.</p>
````
$example_int = 7;
$example_str = "7_string";

if ($example_int === (int)$example_str) {
  # This condition statement will return True
  echo("This will print.");
}
````
