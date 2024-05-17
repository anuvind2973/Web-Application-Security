
# Intro Serialization.

<p align="justify">Serialization is when an object in a programming language (say, a Java or PHP object) is converted into a format that can be stored or transferred. Whereas deserialization refers to the opposite: it’s when the serialized object is read from a file or the network and converted back into an object.</p>

<p align="justify">Insecure deserialization vulnerabilities happen when applications deserialize objects without proper sanitization. An attacker can then manipulate serialized objects to change the program’s flow.</p>

### Perpouse of serialization

* <p align="justify">Serialization enables communication between services and applications by converting object graphs into a byte stream for network transfer. This is vital in distributed systems and web applications for seamless data transmission.</p>
* <p align="justify">Serialization is crucial for storing objects in databases, transforming them into byte streams for efficient storage and later deserialization when retrieval is needed.</p>

# Intro PHP Serialization.

### The unserialize() vulnerability, summarizedPermalink

<p align="justify">When an attacker controls a serialized object that is passed into unserialize(), she can control the properties of the created object. This will then allow her the opportunity to hijack the flow of the application, by controlling the values passed into magic methods like __wakeup().</p>

<p align="justify">The attacker can then execute the code contained in the magic methods using the parameters specified by her, or use the magic methods as a means of starting a POP chain.</p>

<p align="justify">POP stands for Property Oriented Programming, and the name comes from the fact that the attacker can control all of the properties of the deserialized object. Similar to ROP attacks (Return Oriented Programming), POP chains work by chaining code “gadgets” together to achieve the attacker’s ultimate goal. These “gadgets” are code snippets borrowed from the codebase that the attacker uses to further her goal.</p>

### The magic methodsPermalink
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





