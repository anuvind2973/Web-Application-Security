
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

<p align="justify"> Let’s break this serialized string down! The basic structure of a PHP serialized string is “data type: data”. For example, “b” represents a boolean.
```
  b:THE_BOOLEAN;
```
“i” represents an integer.
```
  i:THE_INTEGER;
```
“d” represents a float.
```d:THE_FLOAT;```
”s” represents a string.

s:LENTH_OF_STRING:"ACTUAL_STRING";
“a” represents an array.

a:NUMBER_OF_ELEMENTS:{ELEMENTS}
And finally, “O” represents an object.

O:LENTH_OF_NAME:"CLASS_NAME":NUMBER_OF_PROPERTIES:{PROPERTIES}
So we can see our serialized string here represents an object of the class “User”. It has two properties. The first property has the name “username” and the value “vickie”. The second property has the name “status” and the value “not admin”.

O:4:"User":2:{s:8:"username";s:6:"vickie";s:6:"status";s:9:"not admin";}


#### The magic methodsPermalink
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





