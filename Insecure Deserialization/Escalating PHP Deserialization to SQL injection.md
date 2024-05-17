# SQL injection

<p align="justify"> unserialize() vulnerabilities can also lead to SQL injection if conditions permit it. Here’s an example of how it might be exploited. (This example is taken from owasp.org.)</p>

### Using POP chains to achieve SQL injection

<p align="justify"> Let’s say an application does this somewhere in the code: it defines an Example3 class, and it deserializes unsanitized user input from the POST parameter data.</p>

````
class Example3
{
   protected $obj;

   function __construct()
   {
      // some PHP code...
   }

   function __toString()
   {
      if (isset($this->obj)) return $this->obj->getValue();
   }
}

// some PHP code...

$user_data = unserialize($_POST['data']);

// some PHP code...
````
<p align="justify"> __toString() is a magic function that gets called when a class is treated as a string. In this case, when an Example3 instance is treated as a string, it will return the result of the getValue() method of its $obj property.</p>

<p align="justify"> And let’s say somewhere in the application the class SQL_Row_Value is also defined. It has a method named getValue() and it executes a SQL query. The SQL query takes input from the $_table property of the SQL_Row_Value instance.</p>

````
class SQL_Row_Value
{
   private $_table;

   // some PHP code...

   function getValue($id)
   {
      $sql = "SELECT * FROM {$this->_table} WHERE id = " . (int)$id;
      $result = mysql_query($sql, $DBFactory::getConnection());
      $row = mysql_fetch_assoc($result);

      return $row['value'];
   }
}
````
<p align="justify">An attacker can then achieve SQL injection by controlling the $obj in Example3: the following code will create an Example3 instance with $obj set to a SQL_Row_Value instant with $_table set to the string “SQL Injection”.</p>

````
class SQL_Row_Value
{\
   private $_table = "SQL Injection";
}

class Example3
{
   protected $obj;

   function __construct()
   {
      $this->obj = new SQL_Row_Value;
   }
}

print urlencode(serialize(new Example3));
````

<p align="justify"> This way, whenever the attacker’s Example3 instance is treated as a string, it’s $obj’s get_Value() method will be executed. So the SQL_Row_Value’s get_Value() method will be executed with the $_table string set to “SQL Injection”.</p>

<p align="justify"> The attacker has now achieved limited SQL injection since she can control the string passed into the SQL query ”SELECT * FROM {$this->_table} WHERE id = “ . (int)$id;</p>
