
### Intro Serialization.

<p align="justify">Serialization is when an object in a programming language (say, a Java or PHP object) is converted into a format that can be stored or transferred. Whereas deserialization refers to the opposite: it’s when the serialized object is read from a file or the network and converted back into an object.</p>

<p align="justify">Insecure deserialization vulnerabilities happen when applications deserialize objects without proper sanitization. An attacker can then manipulate serialized objects to change the program’s flow.</p>

### Perpouse of serialization

* <p align="justify">Serialization enables communication between services and applications by converting object graphs into a byte stream for network transfer. This is vital in distributed systems and web applications for seamless data transmission.</p>
* <p align="justify">Serialization is crucial for storing objects in databases, transforming them into byte streams for efficient storage and later deserialization when retrieval is needed.</p>

### The unserialize() vulnerability, summarizedPermalink

<p align="justify">When an attacker controls a serialized object that is passed into unserialize(), she can control the properties of the created object. This will then allow her the opportunity to hijack the flow of the application, by controlling the values passed into magic methods like __wakeup().</p>

<p align="justify">The attacker can then execute the code contained in the magic methods using the parameters specified by her, or use the magic methods as a means of starting a POP chain.</p>

<p align="justify">POP stands for Property Oriented Programming, and the name comes from the fact that the attacker can control all of the properties of the deserialized object. Similar to ROP attacks (Return Oriented Programming), POP chains work by chaining code “gadgets” together to achieve the attacker’s ultimate goal. These “gadgets” are code snippets borrowed from the codebase that the attacker uses to further her goal.</p>


