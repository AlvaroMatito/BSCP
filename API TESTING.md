----
### QUE ES?
El **API Testing** en seguridad consiste en analizar y probar los **endpoints de una API** para encontrar vulnerabilidades en cómo la aplicación **expone, procesa o valida las peticiones**.
Las APIs suelen comunicarse mediante **HTTP/HTTPS usando JSON o XML**, y permiten interactuar directamente con la lógica del backend.
Un atacante puede manipular **parámetros, métodos HTTP, autenticación o estructura de las requests** para acceder a datos que no debería, modificar información o ejecutar acciones privilegiadas.
Los problemas más comunes en APIs incluyen **falta de autenticación, autorización incorrecta, exposición de endpoints internos, IDOR o validación insuficiente de inputs**.
Se previene **validando correctamente los inputs, aplicando controles de autenticación y autorización robustos, limitando los endpoints expuestos y usando esquemas de validación estrictos**.
#### PASOS:
- **ENUMERAR ENDPOINTS DE LA API:** descubrir rutas de la API `/api, /api/user`,  `/api/products`, `/api/users/1`.
- **ANALIZAR LAS REQUESTS DE LA APLICACIÓN:**  mirar qué **parámetros, headers, métodos HTTP y datos JSON** usa la aplicación cuando interactúa con la API.
- **PROBAR DIFERENTES MÉTODOS HTTP:** cambiar el método de la request para ver si el endpoint acepta otros métodos `GET, POST, PUT, PATCH, DELETE, OPTIONS
- **MANIPULAR PARÁMETROS:** modificar los parámetros enviados en la request para comprobar si el backend valida correctamente.
- **PROBAR CAMPOS OCULTOS (MASS ASSIGNMENT):** añadir campos adicionales al JSON para comprobar si el backend los acepta.
### LAB1: EXPLOITING AN API ENDPOINT USING DOCUMENTATION
En este lab vemos un apartado de login y de cambio de correo, si lo hacemos y vemos el flujo de request en el *Http History* podemos ver una request `/api/user/wiener`. Podemos probar a hacer la request solo a `/api` y vemos el *endpoint* de la *API*. Este nos chiva como eliminar los usuarios -> `DELETE /api/user/carlos`.
### LAB2: EXPLOITING SERVER-SIDE PARAMETER POLLUTION IN A QUERY STRING
En este lab nos piden que nos conectemos como *administrator*, vemos que hay un apartado de forgot password si seguimos todo el flujo de request enviando una petición para cambiar la contraseña de *administrator* y miramos el *Http History* vemos una request `/forgot-password`y ademas vemos `/static/js/forgotPassword.js.
Si enviamos ambas request al *repeater* podemos probar a intentar manipular los valores que se pasan por *POST* en `/forgot-password`, para ello añadimos a `username=administrator%26x=y`vemos que nos dice *Parameter is not supported* lo que nos sugiere que la api lo esta interpretando. Probamos con `username=administrator%26field=x%23` y nos dice que *invalid field* es decir es un parametro valido pero su contenido no es el correcto. Lo enviamos al *intruder* y lo atacamos mediante *simple list* usando el diccionario *Server-side variable names*. Descubrimos *email* pero nos devuelve lo que ya habíamos visto antes. Si le echamos un vistazo a `/static/js/forgotPassword.js` vemos que usa *reset_token* por lo que podemos probar `username=administrator%26field=reset_token%23` devolviéndonos el valor del token para resetear la contraseña de administrador. Basta con buscar en la *url*  `/forgot-password?reset_token=token`
### LAB3: FINDING AND EXPLOITING AN USUSED API ENDPOINT
En este laboratorio nos logueamos y vamos al home, vemos que al pinchar en un producto hay un mensaje que llama la atención. Si miramos el *Http History* podemos ver una request a la *API* `/api/products/1/price`. Podemos intentar listar los metodos que estan permitidos cambiando *GET* por *OPTIONS* de esta manera veremos que el método *PATCH* esta habilitado. El método **PATCH** es un **método HTTP que se usa para actualizar parcialmente un recurso** en el servidor. **PATCH solo modifica los campos que se envían en la request**. Veremos que al enviarla con *PATCH* nos dirá que hay un fallo en el *Content-Type* debemos cambiarlo a `application/json` y pues meterle `{}` en el body. Veremos que ahora nos dice que falta el parámetro *price*. Modificamos el valor del producto con `{"price":0}` y bastará con recargar la pagina para que el valor sea 0.
### LAB4: EXPLOITING A MASS ASSIGNMENT VULNERABILITY
En este laboratorio trás loguearnos añadimos un producto al carrito y le damos a comprar, veremos un error de que no tenemos suficiente dinero :( . Si revisamos el *Http History* veremos algunas request tanto *GET* como *POST* a `/api/checkout`. Si prestamos atención veremos que en la respuesta hay un *chosen_discount* a 0. Podemos tratar de ponerlo al 100 para que nos salga gratis mediante *POST*:
`{
`	"chosen_discount":
`		"percentage":0
`	},
`	"chosen_products":[
`		{
`			"product_id":"1",
`			"name":"Lightweight \"l33t\" Leather Jacket",
`			"quantity":1
`			,"item_price":133700
`		}
`	]
`}