
# Intro Serialization.

<p align="justify">Serialization is when an object in a programming language (say, a Java or PHP object) is converted into a format that can be stored or transferred. Whereas deserialization refers to the opposite: it’s when the serialized object is read from a file or the network and converted back into an object.</p>

<p align="justify">Insecure deserialization vulnerabilities happen when applications deserialize objects without proper sanitization. An attacker can then manipulate serialized objects to change the program’s flow.</p>

### Perpouse of serialization

* <p align="justify">Serialization enables communication between services and applications by converting object graphs into a byte stream for network transfer. This is vital in distributed systems and web applications for seamless data transmission.</p>
* <p align="justify">Serialization is crucial for storing objects in databases, transforming them into byte streams for efficient storage and later deserialization when retrieval is needed.</p>

# Intro PHP Serialization.

### Intro to PHP object injection vulnerabilities

<p align="justify">Serialization is when an object in a programming language (say, a Java or PHP object) is converted into a format that can be stored or transferred. Whereas deserialization refers to the opposite: it’s when the serialized object is read from a file or the network and converted back into an object.</p>

<p align="justify">Insecure deserialization vulnerabilities happen when applications deserialize objects without proper sanitization. An attacker can then manipulate serialized objects to change the program’s flow.</p>

<p align="justify">POP stands for Property Oriented Programming, and the name comes from the fact that the attacker can control all of the properties of the deserialized object. Similar to ROP attacks (Return Oriented Programming), POP chains work by chaining code “gadgets” together to achieve the attacker’s ultimate goal. These “gadgets” are code snippets borrowed from the codebase that the attacker uses to further her goal.</p>

#### SerializingPermalink
<p align="justify">When you need to store a PHP object or transfer it over the network, you use serialize() to pack it up.</p>
```
serialize(): PHP object -> plain old string that represents the object
```
When you need to use that data, use unserialize() to unpack and get the underlying object.
```
unserialize(): string containing object data -> original object
```
For example, this code snippet will serialize the object “user”.

```
<?php
class User{
  public $username;
  public $status;
}
$user = new User;
$user->username = 'vickie';
$user->status = 'not admin';
echo serialize($user);
?>
```

<p align="justify">Run the code snippet, and you will get the serialized string that represents the “user” object.</p>

```
O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:9:"not admin";}
```

#### Serialized string structure

<p align="justify"> Let’s break this serialized string down! The basic structure of a PHP serialized string is “data type: data”. For example, “b” represents a boolean.</p>

```
b:THE_BOOLEAN;
```

“i” represents an integer.

```
i:THE_INTEGER;
```
“d” represents a float.

```
d:THE_FLOAT;
```

”s” represents a string.

```
s:LENTH_OF_STRING:"ACTUAL_STRING";
```
“a” represents an array.

```
a:NUMBER_OF_ELEMENTS:{ELEMENTS}
```
And finally, “O” represents an object.

```
O:LENTH_OF_NAME:"CLASS_NAME":NUMBER_OF_PROPERTIES:{PROPERTIES}
```

<p align="justify"> So we can see our serialized string here represents an object of the class “User”. It has two properties. The first property has the name “username” and the value “vickie”. The second property has the name “status” and the value “not admin”.</p>

```
O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:9:"not admin";}
```

#### Deserializing

When you are ready to operate on the object again, you can deserialize the string with unserialize().

```
<?php
class User{
  public $username;
  public $status;
}
$user = new User;
$user->username = 'vickie';
$user->status = 'not admin';
$serialized_string = serialize($user);
$unserialized_data = unserialize($serialized_string);
var_dump($unserialized_data);
var_dump($unserialized_data["status"]);
?>
```
#### Unserialize() under the hood

So how does unserialize() work under the hood? And why does it lead to vulnerabilities?

What are PHP magic methods?

PHP magic methods are function names in PHP that have “magical” properties. Learn more about them here.

<p align="justify">The magic methods that are relevant for us now are __wakeup() and __destruct(). If the class of the serialized object implements any method named __wakeup() and __destruct(), these methods will be executed automatically when unserialize() is called on an object.</p>

##### Step 1: Object instantiation

<p align="justify"> Instantiation is when the program creates an instance of a class in memory. That is what unserialize() does. It takes the serialized string, which specifies the class and the properties of that object. With that data, unserialize() creates a copy of the originally serialized object.</p>

<p align="justify"> It will then search for a function named __wakeup(), and execute code in that function. __wakeup() reconstructs any resources that the object may have. It is used to reestablish any database connections that have been lost during serialization and perform other reinitialization tasks.</p>

##### Step 2: Program uses the object
The program operates on the object and uses it to perform other actions.

##### Step 3: Object destruction
Finally, when no reference to the deserialized object instance exists, __destruct() is called to clean up the object.

##### Exploiting PHP deserialization
When you control a serialized object that is passed into unserialize(), you control the properties of the created object. You might also be able to hijack the flow of the application by controlling the values passed into automatically executed methods like __wakeup() or __destruct().

This is called a PHP object injection. PHP object injection can lead to variable manipulation, code execution, SQL injection, path traversal, or DoS.

#### The magic methods
<p align="justify">There are four magic methods that are particularly useful when trying to exploit an unserialize() vulnerability: __wakeup(), __destruct(), __toString() and __call(). Today, we’re gonna discuss</p>

* What they are
* What they do
And why they are useful for constructing exploits.

#### __wakeup()Permalink

<p align="justify"> __wakeup() is a magic method that is invoked on unserialize(). It is normally used to reestablish any database connections that may have been lost during serialization and perform other reinitialization tasks.</p>

<p align="justify"> It is often useful during an unserialize() exploit because if it is defined for the class, it is automatically called upon object deserialization. Thus, it provides a convenient entry point to the database or to other functions in the code for POP chain purposes.</p>

#### __destruct()Permalink

<p align="justify"> When no reference to the deserialized object instance exists, __destruct() is called. It is invoked on garbage collection and is normally used to clean up references and finish other unfinished businesses associated with the object.</p>

<p align="justify"> As it is used to clean up resources and shut down functionalities, it is very often found that __destruct() contains useful code in terms of exploitation. For example, if a __destruct() method contains code that deletes and cleans up files associated with the object, this might give the attacker an opportunity to mess with the integrity of the filesystem.</p>

#### __toString()Permalink

<p align="justify"> Unlike __wakeup() and __destruct(), the __toString() method is only invoked when the object is treated as a string. (Although if a __toString() method is defined for the class, it is likely that it would get used somewhere.)</p>

<p align="justify"> The __toString() method allows a class to decide how it will react when it is treated as a string. For example, what will print if the object were to be passed into an echo() or print() function?</p>

#### Controlling variable valuesPermalink

<p align="justify">One possible way of exploiting a PHP object injection vulnerability is variable manipulation. For example, you can mess with the values encoded in the serialized string.</p>

````
O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:9:"not admin";}
````

<p align="justify">In this serialize string, you can try to change the value of “status” to “admin”, and see if the application grants you admin privileges.</p>
````
O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:5:"admin";}
````
##### Getting to RCE

<p align="justify"> It’s even possible to achieve RCE using PHP object injection! For example, consider this vulnerable code snippet: (taken from https://www.owasp.org/index.php/PHP_Object_Injection)</p>

###### class Example2

````
{
  private $hook;
  function __construct(){
      // some PHP code...
  }
  function __wakeup(){\
      if (isset($this->hook)) eval($this->hook);
  }
}
// some PHP code...
$user_data = unserialize($_COOKIE['data']);
// some PHP code...
````

<p align="justify"> You can achieve RCE using this deserialization flaw because a user-provided object is passed into unserialize. And the class Example2 has a magic function that runs eval() on user-provided input.</p>

<p align="justify"> To exploit this RCE, you simply have to set your data cookie to a serialized Example2 object with the hook property set to whatever PHP code you want. You can generate the serialized object using the following code snippet:</p>

###### class Example2

````
{
   private $hook = "phpinfo();";
}
print urlencode(serialize(new Example2));
// We need to use URL encoding since we are injecting the object via a URL.
````

<p align="justify"> Passing the above-generated string into the data cookie will cause the code “phpinfo();” to be executed. Once you pass the serialized object into the program, the following is what will happen in detail:</p>

* You pass a serialized Example2 object into the program as the data cookie.
* The program calls unserialize() on the data cookie.
* Because the data cookie is a serialized Example2 object, unserialize() instantiates a new Example2 object.
* unserialize() sees that the Example2 class has __wakeup() implemented, so __wakeup() is called.
* __wakeup() looks for the $hook property of the object, and if it is not NULL, it runs eval($hook).
* $hook is not NULL, and is set to “phpinfo();”, so eval(“phpinfo();”) is run.
* RCE is achieved.





