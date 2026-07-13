# Informe — Proxy SOCKS5 con protocolo de monitoreo

> ITBA — Protocolos de Comunicación
> Trabajo práctico especial

**Integrantes**  

Rocco Perrone — Legajo 65628  
Bautista Pessagno — Legajo 00000  
Rodrigo Hernandez — Legajo 00000  
Lorenzo Mendez — Legajo 00000  

El trabajo consiste en un servidor proxy SOCKS versión 5 (RFC 1928) con autenticación usuario/contraseña (RFC 1929), acompañado de un protocolo propio de monitoreo y configuración en caliente (SMCP) y su cliente de línea de comandos. El servidor atiende múltiples conexiones concurrentes con E/S no bloqueante en un único hilo.

---

## 1. Índice

1. [Índice](#1-índice)
2. [Protocolos diseñados y aplicaciones desarrolladas](#2-protocolos-diseñados-y-aplicaciones-desarrolladas)
  - 2.1. [Aplicaciones desarrolladas](#21-aplicaciones-desarrolladas)
  - 2.2. [Especificación del protocolo SMCP](#22-especificación-del-protocolo-de-monitoreo-smcp)
3. [Problemas encontrados durante el diseño y la implementación](#3-problemas-encontrados-durante-el-diseño-y-la-implementación)
4. [Limitaciones de la aplicación](#4-limitaciones-de-la-aplicación)
5. [Posibles extensiones](#5-posibles-extensiones)
6. [Conclusiones](#6-conclusiones)
7. [Ejemplos de prueba](#7-ejemplos-de-prueba)
8. [Guía de instalación](#8-guía-de-instalación)
9. [Instrucciones para la configuración](#9-instrucciones-para-la-configuración)
10. [Ejemplos de configuración y monitoreo](#10-ejemplos-de-configuración-y-monitoreo)
11. [Documento de diseño del proyecto](#11-documento-de-diseño-del-proyecto)
12. [Bibliografía](#12-bibliografía)

---

## 2. Protocolos diseñados y aplicaciones desarrolladas

### 2.1. Aplicaciones desarrolladas

El proyecto produce dos ejecutables:


| Artefacto    | Descripción                                                                 |
| ------------ | --------------------------------------------------------------------------- |
| `bin/server` | Servidor proxy SOCKS5 y servicio de management (SMCP), en un mismo proceso. |
| `bin/client` | Cliente de monitoreo y configuración que habla SMCP.                        |


Servidor (`bin/server`). Implementa el comando `CONNECT` de SOCKS5 sobre destinos IPv4, IPv6 y FQDN, con autenticación usuario/contraseña (RFC 1929) contra un almacén de usuarios modificable en caliente. Atiende hasta 500 conexiones concurrentes (cada conexión consume dos descriptores sobre un presupuesto de 1024) con E/S no bloqueante multiplexada en un solo hilo.

La única tarea que se ejecuta fuera de ese hilo es la resolución DNS. Como `getaddrinfo(3)` es una llamada bloqueante, ejecutarla en el hilo del servidor congelaría a todas las conexiones mientras se resuelve un nombre. Para evitarlo, el servidor mantiene un pool acotado de hilos trabajadores dedicado exclusivamente a resolver FQDNs: la conexión encola el pedido, sigue su vida en el hilo principal, y cuando la resolución termina el resultado se le entrega de vuelta al selector como un evento más. Que el pool sea acotado (una cantidad fija de hilos, con cola de trabajos pendientes) pone un techo al costo de la concurrencia aun bajo ráfagas de conexiones. 

Además el servidor mantiene métricas de operación en memoria, escribe un registro de accesos persistente en archivo (una línea por intento de conexión) y expone el servicio SMCP en un socket independiente. Soporta apagado ordenado: ante `SIGINT`/`SIGTERM` deja de aceptar y drena las conexiones vivas. La arquitectura interna se describe en la [Sección 11](#11-documento-de-diseño-del-proyecto).

Cliente (`bin/client`). Aplicación interactiva de consola que se conecta al servicio SMCP, se autentica como administrador y ofrece un menú con las operaciones del protocolo: consultar métricas, listar/agregar/eliminar usuarios del proxy, leer y modificar la configuración, consultar el registro de accesos y cambiar la contraseña del administrador. Con `-v` muestra además el comando SMCP crudo enviado y la línea de estado recibida, útil para depuración.

### 2.2. Especificación del protocolo de monitoreo (SMCP)

SOCKS5 Management & Configuration Protocol — Versión 1.0

#### Abstract

Este documento especifica SMCP, un protocolo de aplicación para monitorear y administrar en tiempo de ejecución un servidor proxy SOCKS5. SMCP permite a un administrador consultar métricas de operación, gestionar los usuarios del proxy, modificar parámetros de configuración sin reiniciar el servidor y consultar el registro de accesos.

SMCP es un protocolo independiente de SOCKS v5 (RFC 1928): escucha en un socket pasivo y puerto propios, dentro del mismo proceso servidor.

#### 2.2.1. Terminología

Las palabras clave "DEBE", "DEBERÍA", "PUEDE" y sus variantes se interpretan según el RFC 2119. Además, esta especificación distingue dos conjuntos de credenciales que no deben confundirse:

- Usuario del proxy: credencial usuario/contraseña aceptada por el servicio SOCKS5 (RFC 1929). SMCP administra este conjunto (`ADD-USER`, `DEL-USER`).
- Administrador: credencial que autoriza el uso de SMCP (`AUTH`, `PASSWD`). Es distinta del conjunto de usuarios del proxy.

#### 2.2.2. Modelo de transporte y de sesión

Transporte. SMCP se transporta sobre TCP. El servidor DEBE escuchar en una dirección y puerto configurables (por defecto `127.0.0.1:8080`), independientes de los del servicio SOCKS5.

Sesión. Una sesión es persistente y con estado: el cliente abre una conexión, emite uno o más comandos de forma secuencial y la cierra con `QUIT`. El servidor DEBE procesar los comandos de una sesión en el orden en que llegan y responder en ese mismo orden (un comando, una respuesta).

Cada sesión atraviesa dos estados:

```
        +-----------+   AUTH ok    +----------+
 ---->  |  NO_AUTH  | -----------> |   AUTH   |
        +-----------+              +----------+
             |                          |
           QUIT                       QUIT
             |                          |
             v                          v
          (cerrada)                (cerrada)
```

- NO_AUTH: estado inicial. El servidor SÓLO DEBE aceptar los comandos `AUTH`, `HELP` y `QUIT`. Cualquier otro comando DEBE responder `-ERR not authenticated`.
- AUTH: alcanzado tras un `AUTH` exitoso. Todos los comandos están disponibles.

El servidor DEBE atender las sesiones SMCP de forma no bloqueante y multiplexada en el mismo hilo que el resto del servidor (no se permiten hilos ni I/O bloqueante para atender SMCP).

#### 2.2.3. Formato de los mensajes

Marco (framing). SMCP es un protocolo de texto orientado a líneas.

- Tanto los comandos (cliente → servidor) como las líneas de respuesta (servidor → cliente) terminan con el carácter LF (`0x0A`, `\n`).
- Un `CR` (`0x0D`) inmediatamente anterior al `LF` DEBE ser tolerado y descartado. El cliente DEBERÍA enviar sólo `LF`.
- Una línea NO DEBE exceder los 4096 bytes incluyendo el terminador. Si el servidor recibe una línea más larga, DEBE responder `-ERR line too long` y descartar los bytes hasta el próximo `LF`.
- La codificación es ASCII de 7 bits. Los bytes fuera de `0x20`–`0x7E` (salvo el terminador) en un comando producen `-ERR invalid`.

Tanto cliente como servidor DEBEN tolerar lecturas y escrituras parciales: un comando o una respuesta pueden llegar fragmentados en varios segmentos TCP, o varios comandos pueden llegar en un mismo segmento (pipelining). El parseo DEBE ser reentrante y conservar el progreso entre lecturas.

Sintaxis de un comando.

```
comando   = palabra *( SP argumento ) LF
palabra   = 1*(ALPHA / "-")
argumento = 1*(VCHAR)
SP        = %x20
```

- La palabra de comando es case-insensitive (`METRICS`, `metrics` y `Metrics` son equivalentes). Los argumentos son case-sensitive.
- Los argumentos se separan por un espacio. En consecuencia, los argumentos (por ejemplo nombres de usuario o contraseñas creados vía SMCP) NO PUEDEN contener espacios. Esta es una limitación deliberada del protocolo.
- El número de argumentos es fijo por comando. Argumentos de más o de menos producen `-ERR invalid`.

Sintaxis de una respuesta. Toda respuesta comienza con una línea de estado:

```
estado = ("+OK" / "-ERR") [ SP texto ] LF
```

- `+OK` indica éxito; `-ERR` indica error. El `texto` es informativo y legible.
- Las respuestas de enumeración (listas de pares clave/valor o de registros) usan marco prefijado por cantidad: la línea de estado es `+OK <n>`, donde `<n>` es un entero decimal, y a continuación siguen exactamente `<n>` líneas de datos. No hay línea terminadora ni dot-stuffing.
  ```
  +OK 3
  active_connections 12
  historical_connections 4033
  total_bytes 8823123
  ```

Los nombres de clave usan `snake_case`. La elección del marco prefijado por cantidad frente a un terminador `.` también se justifica allí.

#### 2.2.4. Comandos

En las descripciones, `<x>` es un argumento obligatorio y `[x]` uno opcional.


| Comando                           | Estado requerido | Descripción                                                                                                                        |
| --------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH <usuario> <contraseña>`     | `NO_AUTH`        | Autentica al administrador y habilita los comandos privilegiados de la sesión.                                                     |
| `METRICS`                         | `AUTH`           | Devuelve métricas actuales del proxy, como conexiones activas, histórico de conexiones, bytes transferidos y cantidad de usuarios. |
| `LIST-USERS`                      | `AUTH`           | Lista los nombres de usuarios habilitados para autenticarse contra el proxy SOCKS5.                                                |
| `ADD-USER <usuario> <contraseña>` | `AUTH`           | Agrega una credencial de usuario del proxy, efectiva para nuevas conexiones SOCKS5.                                                |
| `DEL-USER <usuario>`              | `AUTH`           | Elimina una credencial de usuario del proxy sin cerrar conexiones ya establecidas.                                                 |
| `GET-CONFIG`                      | `AUTH`           | Devuelve los parámetros de configuración modificables en tiempo de ejecución.                                                      |
| `SET <clave> <valor>`             | `AUTH`           | Modifica un parámetro de configuración válido, respetando el rango definido para esa clave.                                        |
| `LOG [n]`                         | `AUTH`           | Devuelve los últimos registros de acceso, del más reciente al más antiguo.                                                         |
| `PASSWD <nueva-contraseña>`       | `AUTH`           | Cambia la contraseña del administrador para nuevas sesiones.                                                                       |
| `HELP`                            | cualquiera       | Devuelve la lista de comandos disponibles.                                                                                         |
| `QUIT`                            | cualquiera       | Cierra la sesión SMCP de forma ordenada.                                                                                           |


##### AUTH — autenticación

```
AUTH <usuario> <contraseña>
```

Autentica al administrador. DEBE ser el primer comando de toda sesión que requiera operaciones privilegiadas. En caso de éxito la sesión pasa al estado AUTH.

- Éxito: `+OK authenticated`
- Credenciales inválidas: `-ERR bad credentials`
- Ya autenticado: `-ERR already authenticated`

El servidor NO DEBE revelar si el fallo se debió al usuario o a la contraseña.

##### METRICS — métricas de operación

```
METRICS
```

Devuelve las métricas actuales como pares `clave valor` (una por línea). Los valores son enteros decimales no negativos. 

```
+OK 7
active_connections 12
historical_connections 4033
max_active_connections 87
bytes_client_to_origin 4410000
bytes_origin_to_client 4413123
total_bytes 8823123
users_count 4
```

##### LIST-USERS — listar usuarios del proxy

```
LIST-USERS
```

Devuelve los nombres de los usuarios del proxy, uno por línea. Las contraseñas NUNCA se devuelven.

```
+OK 2
pablito
juana
```

##### ADD-USER — alta de usuario del proxy

```
ADD-USER <usuario> <contraseña>
```

Da de alta un usuario del proxy. El cambio tiene efecto inmediato: nuevas conexiones SOCKS5 podrán autenticarse con esa credencial.

- Éxito: `+OK user added`
- Ya existe: `-ERR user exists`
- Límite alcanzado: `-ERR store full`
- Usuario/contraseña vacío, con espacios o demasiado largo (> 255 bytes): `-ERR invalid`

##### DEL-USER — baja de usuario del proxy

```
DEL-USER <usuario>
```

Elimina un usuario del proxy. Las conexiones SOCKS5 ya establecidas por ese usuario NO se cierran; sólo se impiden nuevas autenticaciones.

- Éxito: `+OK user removed`
- No existe: `-ERR no such user`

##### GET-CONFIG — leer configuración

```
GET-CONFIG
```

Devuelve los parámetros de configuración modificables como pares `clave valor`.

```
+OK 3
conn_timeout 60
io_buffer_size 4096
max_connections 500
```

##### SET — modificar configuración

```
SET <clave> <valor>
```

Modifica un parámetro de configuración en tiempo de ejecución. 

- Éxito: `+OK <clave> = <valor>`
- Clave desconocida: `-ERR unknown key`
- Valor fuera de rango o mal formado: `-ERR invalid value`

##### LOG — consultar registro de accesos

```
LOG [n]
```

Devuelve los últimos `n` registros de acceso, del más reciente al más antiguo. Si se omite `n`, el servidor DEBE usar un valor por defecto (RECOMENDADO: 10). Si `n` excede la cantidad de registros almacenados, se devuelven todos los disponibles. El servidor PUEDE además imponer un tope al valor de `n` para acotar el tamaño de la respuesta (esta implementación: 50).

```
+OK 2
2026-07-09T14:22:07Z pablito CONNECT 1.2.3.4:80 CONN-REFUSED
2026-07-09T14:22:01Z pablito CONNECT example.com:443 OK
```

##### PASSWD — cambiar contraseña del administrador

```
PASSWD <nueva-contraseña>
```

Cambia la contraseña del administrador de la sesión actual. Tiene efecto inmediato para nuevas sesiones; la sesión en curso permanece autenticada.

- Éxito: `+OK password changed`
- Contraseña vacía, con espacios o demasiado larga: `-ERR invalid`

##### HELP — ayuda

```
HELP
```

Devuelve la lista de comandos disponibles, uno por línea. Disponible en cualquier estado.

##### QUIT — cerrar sesión

```
QUIT
```

Cierra la sesión de forma ordenada. El servidor responde `+OK bye` y luego cierra la conexión. Disponible en cualquier estado.

#### 2.2.5. Métricas

El servidor DEBE exponer al menos las siguientes métricas. Las métricas son volátiles: se reinician al reiniciar el servidor.


| Clave                    | Tipo | Descripción                                              |
| ------------------------ | ---- | -------------------------------------------------------- |
| `active_connections`     | u64  | Conexiones SOCKS5 activas en este instante.              |
| `historical_connections` | u64  | Conexiones SOCKS5 aceptadas desde el arranque.           |
| `max_active_connections` | u64  | Pico histórico de conexiones concurrentes.               |
| `bytes_client_to_origin` | u64  | Bytes relayados de cliente a origen.                     |
| `bytes_origin_to_client` | u64  | Bytes relayados de origen a cliente.                     |
| `total_bytes`            | u64  | Suma de ambas direcciones.                               |
| `users_count`            | u64  | Cantidad de usuarios del proxy configurados actualmente. |


Una implementación PUEDE exponer pares `clave valor` adicionales; el cliente DEBE tolerar claves que no conozca.

#### 2.2.6. Configuración

Claves aceptadas por `SET`/`GET-CONFIG`:


| Clave             | Tipo | Rango                | Semántica                                                                         |
| ----------------- | ---- | -------------------- | --------------------------------------------------------------------------------- |
| `conn_timeout`    | u32  | 1 .. 3600 (segundos) | Tiempo de inactividad tras el cual una conexión SOCKS5 se cierra. Afecta a todas. |
| `max_connections` | u32  | 1 .. límite duro     | Tope de conexiones SOCKS5 concurrentes. Se aplica como límite blando al aceptar.  |
| `io_buffer_size`  | u32  | 512 .. 65536 (bytes) | Tamaño del buffer de relay por conexión. Sólo afecta a conexiones nuevas.         |


Notas de semántica:

- `max_connections` sólo puede reducirse por debajo del límite duro con el que se creó el multiplexor; no puede aumentarse por encima de él. Al reducirlo, las conexiones existentes NO se cierran; sólo se rechazan nuevas por encima del tope.
- `io_buffer_size` NO DEBE alterar los buffers de conexiones ya establecidas.

#### 2.2.7. Registro de accesos

Cada registro de acceso describe un intento de conexión de un usuario del proxy a un destino. A diferencia de las métricas (que PUEDEN ser volátiles), el registro de accesos DEBE ser persistente: el servidor lo escribe, una línea por intento de conexión, en un archivo de texto en modo append (su ruta se configura al iniciar el servidor). Así sobrevive a reinicios y queda disponible para consulta offline (p.ej. ante una queja externa recibida días después).

El comando `LOG [n]` devuelve las últimas `n` líneas de ese archivo como vista de conveniencia sobre el protocolo; el archivo sigue siendo la fuente de verdad.

Formato de un registro (una línea, idéntico en el archivo y en la respuesta a `LOG`):

```
registro = timestamp SP usuario SP comando SP destino SP resultado
timestamp = fecha-hora ISO-8601 en UTC, p.ej. 2026-07-09T14:22:01Z
usuario   = nombre del usuario del proxy, o "-" si fue anónimo
comando   = "CONNECT"
destino   = host ":" puerto   (host = IPv4 / IPv6 / FQDN según lo pedido)
resultado = "OK" / "CONN-REFUSED" / "HOST-UNREACH" / "NET-UNREACH"
          / "TTL-EXPIRED" / "CMD-NOT-SUPPORTED" / "GENERAL-FAILURE"
```

Ejemplo:

```
2026-07-09T14:22:01Z pablito CONNECT example.com:443 OK
```

#### 2.2.8. Códigos y mensajes de error

Todo error se reporta con una línea `-ERR <texto>`. Los codigos siguientes son transversales a todos los comandos:


| Texto               | Situación                                |
| ------------------- | ---------------------------------------- |
| `not authenticated` | Comando privilegiado en estado NO_AUTH.  |
| `unknown command`   | Palabra de comando no reconocida.        |
| `invalid`           | Cantidad o forma de argumentos inválida. |
| `line too long`     | Línea que excede 4096 bytes.             |


#### 2.2.9. Consideraciones de seguridad

- Las credenciales viajan en texto plano. SMCP DEBERÍA escuchar sólo en `127.0.0.1` (interfaz de loopback) por defecto; exponerlo en una interfaz de red requiere un canal seguro externo (p.ej. un túnel SSH).
- El servidor NO DEBE distinguir en la respuesta entre "usuario inexistente" y "contraseña incorrecta" durante `AUTH`.
- El límite de longitud de línea acota el consumo de memoria por sesión y previene ataques de agotamiento.

#### 2.2.10. Ejemplo de sesión completa

```
C: (abre conexión TCP a 127.0.0.1:8080)
C: AUTH admin s3cret
S: +OK authenticated
C: METRICS
S: +OK 7
S: active_connections 12
S: historical_connections 4033
S: max_active_connections 87
S: bytes_client_to_origin 4410000
S: bytes_origin_to_client 4413123
S: total_bytes 8823123
S: users_count 3
C: ADD-USER pablito pass1234
S: +OK user added
C: SET conn_timeout 30
S: +OK conn_timeout = 30
C: QUIT
S: +OK bye
S: (cierra conexión)
```

Cada comando restante (`LIST-USERS`, `DEL-USER`, `GET-CONFIG`, `LOG`, `PASSWD`, `HELP`) sigue el mismo patrón.

Nota: el servidor PUEDE enviar una línea de saludo `+OK SMCP 1.0 ready` al aceptar la conexión; esta implementación no la envía. El cliente DEBE tolerar su presencia o ausencia.

#### 2.2.11. Gramática ABNF (resumen)

```abnf
session       = greeting *interaction
greeting      = "+OK" SP "SMCP" SP version SP "ready" LF   ; opcional

interaction   = command / response

command       = ( auth / metrics / list-users / add-user / del-user
                / get-config / set / log / passwd / help / quit ) LF
auth          = "AUTH" SP token SP token
metrics       = "METRICS"
list-users    = "LIST-USERS"
add-user      = "ADD-USER" SP token SP token
del-user      = "DEL-USER" SP token
get-config    = "GET-CONFIG"
set           = "SET" SP token SP token
log           = "LOG" [ SP 1*DIGIT ]
passwd        = "PASSWD" SP token
help          = "HELP"
quit          = "QUIT"

response      = status-line *( data-line )
status-line   = ( "+OK" / "-ERR" ) [ SP text ] LF
data-line     = text LF
token         = 1*VCHAR            ; sin espacios
text          = *( VCHAR / SP )
version       = 1*DIGIT "." 1*DIGIT

SP            = %x20
LF            = %x0A
DIGIT         = %x30-39
VCHAR         = %x21-7E
```

#### 2.2.12. Decisiones de diseño del protocolo

- Transporte TCP. Una sesión administrativa es interactiva y de duración prolongada (el administrador observa métricas mientras permanece conectado) y requiere entrega ordenada y confiable de comandos y respuestas.
- Texto orientado a líneas (vs. binario). Simplifica la depuración y la inspección manual durante el desarrollo, y el volumen de datos administrativos es bajo: el costo de serializar texto es despreciable frente al tráfico del proxy.
- Marco prefijado por cantidad (vs. terminador `.` estilo POP3/SMTP). Evita la ambigüedad de un dato que comience con `.` y el consiguiente dot-stuffing; el cliente lee la cantidad y luego exactamente esa cantidad de líneas.
- Claves en `snake_case`. Los nombres de clave de métricas y configuración coinciden 1:1 con los campos internos de la implementación, eliminando tablas de traducción entre la especificación y el código. Se usa una única convención para métricas y configuración por consistencia.
- Registro de accesos en archivo (persistente), métricas en memoria (volátil). El caso de uso del registro (una queja externa que llega días después) exige durabilidad; por eso se escribe append a un archivo —la fuente de verdad— y `LOG` sólo devuelve las últimas líneas como vista. Escribir a un archivo regular es compatible con el modelo no bloqueante: la restricción aplica a la E/S de sockets, no a los archivos (que no son pollables y se consideran siempre listos).
- Dos convenciones de nombres según la clase de token. Los comandos usan `KEBAB-CASE` en mayúsculas (son verbos del protocolo, alineados con los subcomandos del cliente CLI); las claves de datos usan `snake_case` (alineadas con los campos internos). La distinción de mayúsculas/minúsculas ya separa ambas clases de tokens; el separador sólo refuerza ese límite.

---

## 3. Problemas encontrados durante el diseño y la implementación

Latencia en el relay por el orden de despacho. En la primera versión del relay, los bytes leídos de un extremo quedaban en el buffer hasta que el selector reportara al otro extremo listo para escribir, en una iteración posterior del loop: cada chunk pagaba una vuelta extra de `pselect` y syscalls de más. Se corrigió de la siguiente manera, tras cada lectura se intenta escribir inmediatamente lo bufferizado al otro extremo, y sólo si el `send` no completa (`EWOULDBLOCK`) se delega el resto al evento de escritura del selector.

Sincronización con el pool de DNS. La resolución en hilos aparte introdujo los únicos problemas de concurrencia real del proyecto. Hubo que definir con cuidado qué campos de la conexión puede tocar cada hilo y bajo qué lock, porque el hilo principal y los trabajadores comparten el `conn`; y resolver la cancelación: si la conexión se cierra mientras su `getaddrinfo` sigue en vuelo, el trabajo debe marcarse como cancelado y su resultado descartarse sin que ningún hilo escriba sobre memoria liberada. La notificación del resultado al selector (vía señal y `handle_block`) permitió que toda esa complejidad quede encapsulada: los handlers de la máquina de estados nunca ven concurrencia.

El techo de `select(2)`. Al construir la batería de stress apareció el límite de `FD_SETSIZE` (1024 descriptores): con dos descriptores por conexión más los reservados, el servidor admite hasta 500 conexiones simultáneas. El límite obligó además a presupuestar descriptores explícitamente (`max_connections` se deriva de esa cuenta) y a que el generador de carga y el backend de prueba usen `poll(2)`, para que el techo medido fuera el del servidor y no el de las herramientas que lo miden.

---

## 4. Limitaciones de la aplicación

Estado administrativo no persistente. Los cambios hechos via SMCP —usuarios agregados con `ADD-USER`, parámetros modificados con `SET` y la contraseña de administrador cambiada con `PASSWD`— viven sólo en memoria: al reiniciar el servidor se vuelve a la configuración por defecto y a los usuarios pasados por línea de comandos (`-u`). El almacén de usuarios además está acotado a 100 entradas y guarda las contraseñas en texto plano en memoria, sin hashing. La única pieza durable es el registro de accesos, que por diseño se escribe a archivo.

Resolución DNS. El pool de resolución tiene una cantidad fija de hilos (4): a lo sumo cuatro `getaddrinfo` corren en simultáneo y el resto de los pedidos espera en la cola. Ante una ráfaga de conexiones a FQDNs —o unos pocos nombres cuya resolución es lenta— la espera en cola se suma a la latencia de establecimiento de esas conexiones. Es el trade-off elegido: el techo de hilos acota el costo de la concurrencia, a cambio de que la resolución pueda volverse el cuello de botella. Las conexiones a direcciones IP literales no pasan por el pool y no se ven afectadas.

---

## 5. Posibles extensiones

Persistencia de usuarios y configuración. La contracara directa de la limitación de la Sección 4: guardar el almacén de usuarios y los parámetros modificados en caliente en un archivo de configuración —con las contraseñas hasheadas, al estilo `htpasswd`— que el servidor lea al arrancar y reescriba ante cada `ADD-USER`/`DEL-USER`/`SET`/`PASSWD`. Así los cambios administrativos sobrevivirían a los reinicios sin depender de la línea de comandos, y el cambio de contraseña del administrador dejaría de ser efímero.

Mejor observabilidad. El diseño de SMCP ya lo permite sin romper compatibilidad. Candidatas naturales: bytes y conexiones por usuario, destinos más frecuentes, errores de conexión por tipo, y tiempos de resolución DNS. Sobre eso podría sumarse un `LOG` con filtro por usuario y un modo *subscribe* en el que el servidor empuje métricas periódicamente a la sesión, evitando el polling.

Rate limiting por usuario. Con la autenticación y la contabilización de bytes ya presentes, el servidor tiene la información necesaria para imponer cuotas por usuario: un tope de conexiones simultáneas o de bytes por unidad de tiempo. La aplicación encaja naturalmente en el modelo existente —al exceder la cuota se deja de pedir `OP_READ` sobre esa conexión, la misma contrapresión que ya ejercen los buffers llenos— y las cuotas serían un parámetro más de `SET`/`GET-CONFIG`.

---

## 6. Conclusiones

El trabajo confirma que el modelo de un solo hilo con E/S no bloqueante es suficiente —y eficiente— para una carga I/O-bound como la de un proxy: el servidor pasa la mayor parte del tiempo esperando a la red, y un único hilo multiplexado atiende esa espera para cientos de conexiones sin el costo en memoria y cambios de contexto de un hilo por conexión. La batería de estrés lo respalda: 500 túneles simultáneos con integridad de datos verificada, sostenidos durante un minuto con consumo de recursos estable. El techo, de hecho, no lo puso el modelo sino la interfaz elegida para implementarlo (`select(2)` y su `FD_SETSIZE`).

Pero la afirmación vale exactamente para eso: trabajo I/O-bound expresable como eventos no bloqueantes. Todo lo que no puede ceder el control al event loop —cómputo intensivo, o llamadas cuya interfaz es inherentemente bloqueante— sigue necesitando hilos. En este proyecto ese caso existió desde el inicio: la resolución de FQDNs, donde `getaddrinfo(3)` no ofrece variante no bloqueante y ejecutarla en el hilo del selector congelaría a todas las conexiones por culpa de una sola. La respuesta no fue abandonar el modelo sino confinarlo: un pool acotado de hilos ejecuta el trabajo bloqueante y reingresa el resultado al selector como un evento más, de modo que la concurrencia queda encapsulada en un módulo y el resto del servidor conserva la simplicidad de razonar en un solo hilo. La conclusión general es esa: el modelo de eventos debe ser la regla, y los hilos, la excepción deliberada y acotada para lo que el modelo no puede expresar.

---

## 7. Ejemplos de prueba

### 7.1. Pruebas unitarias

El proyecto incluye una batería de pruebas unitarias con el framework [Check](https://libcheck.github.io/check/), una por módulo (buffer, selector, stm, parsers de negociación/auth/request, handler SOCKS5, SMCP y su parser, usuarios, métricas, configuración, registro de accesos, utilidades de red, parser genérico y cliente):

```sh
make test       # compila y ejecuta toda la batería bajo bin/test/
```

### 7.2. Pruebas funcionales

Con el servidor corriendo (`./bin/server -u pablito:pass1234 -a admin:s3cret`) se verifica con cualquier cliente SOCKS5:

```sh
# destino FQDN: socks5h delega la resolución DNS en el proxy
curl -x socks5h://pablito:pass1234@127.0.0.1:1080 https://example.com/

# destino IP literal: curl resuelve localmente y el proxy recibe la dirección
curl -x socks5://pablito:pass1234@127.0.0.1:1080 http://93.184.215.14/
```

Y los caminos de error, junto con su efecto observable:

```sh
# credenciales inválidas: el handshake falla en la fase de autenticación
curl -x socks5h://pablito:incorrecta@127.0.0.1:1080 https://example.com/

# destino que rechaza la conexión: el cliente recibe el error SOCKS5
# y el intento queda registrado en access.log con resultado CONN-REFUSED
curl -x socks5h://pablito:pass1234@127.0.0.1:1080 http://127.0.0.1:9/
tail -1 access.log
```

El servicio SMCP se ejercita con el cliente provisto (`./bin/client -a admin:s3cret`) o manualmente con `nc 127.0.0.1 8080`. Para verificar la configuración en caliente: `SET conn_timeout 5`, abrir una conexión por el proxy, dejarla inactiva y observar que el reaper la cierra al superar ese tiempo de inactividad (con la granularidad del barrido periódico, que corre a lo sumo cada 10 segundos).

### 7.3. Pruebas de estrés

Las pruebas de estrés (`stress/`, documentada en `docs/stress-testing.md`) es una prueba de integración que levanta el servidor real entre un generador de carga y un echo server locales, y contrasta lo transferido con las métricas reportadas por SMCP. Generador y backend usan `poll(2)` para que el límite medido sea el del servidor y no el de las herramientas. Ejecuta cuatro escenarios:

- Capacidad: establece 500 túneles autenticados simultáneos, valida 1 KiB distinto por túnel y los sostiene 10 segundos, contrastando con `METRICS`.
- Máximo observado: busca el techo real de conexiones simultáneas por incrementos hasta el primer fallo.
- Throughput: transfiere 64 MiB con concurrencias 1, 50, 100, 250 y 500 (tres repeticiones por nivel) y reporta la mediana y la degradación respecto de una conexión.
- Soak: mantiene 500 túneles durante 60 segundos validando tráfico cada segundo, con muestras de CPU y RSS del proceso servidor.

Un escenario falla ante conexiones rechazadas, timeouts, corrupción de datos, métricas inconsistentes o la terminación del servidor. Cada corrida deja sus resultados (`results.json`, `throughput.csv`, `report.md` y los logs de los procesos) bajo `stress/results/<timestamp>/`.

```sh
make stress     # requiere Linux; en macOS, correrlo dentro del entorno Docker (§8.3)
```

Las mediciones se hacen sobre loopback con los tres procesos compartiendo la máquina, por lo que sirven para comparar la degradación entre niveles de concurrencia, no como capacidad absoluta en una red real.

---

## 8. Guía de instalación

### 8.1. Requisitos

- `gcc` con soporte para C11.
- `make`.
- [Check](https://libcheck.github.io/check/) (opcional, sólo para `make test`).

### 8.2. Compilación

Desde la raíz del proyecto:

```sh
make            # compila servidor y cliente
make server     # sólo el servidor
make client     # sólo el cliente
make clean      # elimina los artefactos generados
```

Los binarios quedan en `bin/server` y `bin/client`; los objetos intermedios se generan bajo `obj/`. No se requiere instalación adicional: los ejecutables son autocontenidos.

### 8.3. Alternativa: entorno Linux con Docker

El proyecto puede compilarse dentro de un contenedor Linux; Docker monta el directorio del proyecto en `/workspace`, así que los artefactos aparecen igualmente en `bin/` y `obj/`:

```sh
docker compose build
docker compose run --rm --service-ports dev
# dentro del contenedor:
make && make test
./bin/server -L 0.0.0.0
```

Con `--service-ports` los puertos SOCKS (`1080`) y de management (`8080`) quedan publicados en el host. Al alternar entre macOS y Linux conviene ejecutar `make clean` para no reutilizar objetos compilados para el otro sistema.

---

## 9. Instrucciones para la configuración

### 9.1. Servidor

```sh
./bin/server [OPCIÓN]...
```


| Opción            | Descripción                                                 | Default      |
| ----------------- | ----------------------------------------------------------- | ------------ |
| `-l <dirección>`  | dirección de escucha del proxy SOCKS                        | `0.0.0.0`    |
| `-p <puerto>`     | puerto de escucha del proxy SOCKS                           | `1080`       |
| `-L <dirección>`  | dirección de escucha del servicio de management             | `127.0.0.1`  |
| `-P <puerto>`     | puerto de escucha del servicio de management                | `8080`       |
| `-u <usr>:<pass>` | credencial habilitada para el proxy (hasta 10 veces)        | —            |
| `-a <usr>:<pass>` | credencial del administrador para el servicio de management | —            |
| `-o <path>`       | archivo persistente del registro de accesos                 | `access.log` |
| `-h`              | imprime la ayuda y termina                                  | —            |


### 9.2. Cliente de management

```sh
./bin/client [-v] [-L addr] [-P port] [-a admin:pass]
```


| Opción            | Descripción                                        | Default     |
| ----------------- | -------------------------------------------------- | ----------- |
| `-L <dirección>`  | dirección del servicio de management               | `127.0.0.1` |
| `-P <puerto>`     | puerto del servicio de management                  | `8080`      |
| `-a <usr>:<pass>` | credencial de administrador (si se omite, la pide) | —           |
| `-v`              | muestra el comando SMCP crudo y la línea de estado | —           |
| `-h`              | imprime la ayuda y termina                         | —           |


### 9.3. Configuración en tiempo de ejecución

Los parámetros `conn_timeout`, `max_connections` e `io_buffer_size` se modifican sin reiniciar el servidor mediante el comando `SET` de SMCP, ya sea con el cliente provisto o con cualquier herramienta de línea (`nc`).

---

## 10. Ejemplos de configuración y monitoreo

Arranque del servidor con un usuario del proxy y un administrador:

```sh
./bin/server -u pablito:pass1234 -a admin:s3cret -o access.log
```

Uso del proxy desde cualquier cliente SOCKS5, por ejemplo `curl` (`socks5h` delega la resolución DNS en el proxy):

```sh
curl -x socks5h://pablito:pass1234@127.0.0.1:1080 https://example.com/
```

Monitoreo y configuración con el cliente provisto:

```sh
./bin/client -a admin:s3cret
```

El cliente presenta un menú interactivo (métricas, usuarios, configuración, logs, cambio de contraseña). Como SMCP es un protocolo de texto, la misma sesión puede reproducirse con `nc 127.0.0.1 8080`.

---

## 11. Documento de diseño del proyecto

El servidor está construido sobre un modelo orientado a eventos, no bloqueante y de un solo hilo. Toda la entrada/salida de red se multiplexa con un selector propio basado en `pselect(2)`, y cada conexión se modela como una máquina de estados independiente que avanza a medida que el selector le entrega eventos de lectura y escritura. La única excepción al hilo único es un pool acotado de hilos para la resolución DNS, que evita que un `getaddrinfo(3)` bloqueante frene al resto de las conexiones.

El código se organiza separando lo genérico y reutilizable (`src/shared/`) de la lógica específica del protocolo (`src/server/`) y del cliente de administración (`src/client/`):

```
src/shared/   selector, máquina de estados, buffer, parser genérico,
              utilidades de red y de argumentos (comunes a server y client)
src/server/   handler SOCKS5, negociación, auth, request, relay,
              pool DNS, protocolo de management (SMCP) y estado runtime
src/client/   cliente CLI de monitoreo y configuración
```

A grandes rasgos, el proceso servidor levanta dos sockets pasivos dentro del mismo `main()` y el mismo event loop: uno para el proxy SOCKS5 y otro para el servicio de management. Ambos se registran en el selector con un handler de accept propio, de modo que cada conexión entrante instancia una máquina de estados distinta según el socket por el que llegó:

Una vez armados los sockets, registrado el pool de DNS e instalados los handlers de señales, todo el trabajo del servidor ocurre dentro de un único bucle principal. En cada iteración el loop hace tres cosas, y en ese orden:

```c
while (true) {
    selector_select(selector);        /* 1. bloquea hasta evento o timeout */
    socks5_reap_idle(selector);       /* 2. cierra conexiones inactivas    */
    if (terminate) { /* ... */ }      /* 3. apagado ordenado ante señal    */
}
```

1. Despacho de eventos. `selector_select` se bloquea en `pselect` hasta que algún descriptor está listo (o hasta el timeout de 10 s) y despacha los callbacks correspondientes: aceptar una conexión nueva en un socket pasivo, hacer avanzar una máquina de estados SOCKS5/SMCP ante un evento de lectura/escritura, o reingresar una conexión cuya resolución DNS terminó (`notify_block`). Como toda la E/S es no bloqueante y ningún callback se bloquea, una sola vuelta del loop atiende a todas las conexiones que tuvieron actividad.
2. Reaper de inactividad. Tras cada despacho se recorren las conexiones activas y se cierran las que superaron su timeout de inactividad. El timeout del `pselect` garantiza que este barrido corra periódicamente aunque no haya tráfico.
3. Apagado ordenado. Ante la primera señal `SIGINT`/`SIGTERM` (que sólo incrementa un contador y interrumpe el `pselect`), el loop deja de aceptar —desregistra y cierra ambos sockets pasivos— y drena las conexiones que siguen vivas hasta que no queda ninguna. Una segunda señal fuerza la salida inmediata. Recién entonces se rompe el `while` y se liberan los recursos.

Las subsecciones siguientes describen cada componente técnico principal.

### 11.1. Selector de E/S (`selector.c` / `selector.h`)

Es el corazón del modelo de concurrencia: un multiplexor de entrada/salida que permite atender muchos descriptores en un único hilo sin bloquearse en ninguno. Esconde la implementación concreta (`pselect`) detrás de una API de registración por descriptor.

El usuario registra un `fd` indicando un interés (leer y/o escribir) y un conjunto de callbacks. Cuando el descriptor está listo, el selector despacha el callback correspondiente:

```c
typedef struct fd_handler {
    void (*handle_read)  (struct selector_key *key);
    void (*handle_write) (struct selector_key *key);
    void (*handle_block) (struct selector_key *key);
    void (*handle_close) (struct selector_key *key);
} fd_handler;
```

Dos decisiones de diseño importantes:

- Los handlers no deben bloquearse, porque demorarían al resto de los descriptores. Cuando una tarea sí requiere bloquearse (la resolución DNS), se descarga en otro hilo y luego se avisa al selector con `selector_notify_block`. Esa notificación usa una señal (`SIGALRM`, configurada en `selector_init`), y el resultado se presenta a los handlers como un evento `handle_block` durante la iteración normal, sin que el handler tenga que preocuparse por la concurrencia.
- El bloqueo con `pselect` tiene un timeout (10 s), lo que le da al loop principal oportunidad de ejecutar tareas periódicas —como cerrar conexiones inactivas— aunque no haya tráfico.

### 11.2. Motor de máquinas de estados (`stm.c` / `stm.h`)

Un motor genérico y liviano de máquinas de estados cuyos eventos son, justamente, los del selector. Cada estado se identifica con un entero (de un `enum`) y se describe con un conjunto de callbacks:

```c
struct state_definition {
    unsigned state;
    void     (*on_arrival)    (const unsigned state, struct selector_key *key);
    void     (*on_departure)  (const unsigned state, struct selector_key *key);
    unsigned (*on_read_ready) (struct selector_key *key);
    unsigned (*on_write_ready)(struct selector_key *key);
    unsigned (*on_block_ready)(struct selector_key *key);
};
```

Los callbacks `on_*_ready` devuelven el próximo estado; el motor se encarga de disparar `on_departure`/`on_arrival` en las transiciones. Este mecanismo es el que permite que cada conexión progrese por las fases del protocolo sin necesitar un hilo propio: el estado de avance vive en la estructura de la conexión, no en la pila de un hilo.

### 11.3. Buffer de E/S (`buffer.c` / `buffer.h`)

Un buffer lineal con acceso directo pensado para E/S, que mantiene punteros separados de lectura y escritura sobre un mismo arreglo, con invariante `read ≤ write ≤ limit`. No es un buffer circular: los punteros sólo avanzan, sin dar la vuelta al llegar al límite; el espacio se recupera por compactación (ver más abajo). Esto mantiene los datos pendientes siempre contiguos, de modo que cada lectura o escritura se resuelve con una única syscall, sin la partición en dos tramos que impone el wraparound. El almacenamiento lo provee el llamador (`buffer_init(b, n, data)`). La clave del diseño es que no copia datos: en lugar de recibir bytes, expone punteros crudos al arreglo interno para que las syscalls escriban y lean directamente sobre él. Cada operación es de dos pasos —pedir el puntero, avisar cuánto se usó—:

```c
/* llenar el buffer desde un socket */
uint8_t *ptr = buffer_write_ptr(b, &space); /* dónde y cuánto se puede escribir */
n = recv(fd, ptr, space, 0);
buffer_write_adv(b, n);                     /* avanza el puntero de escritura   */

/* drenar el buffer hacia otro socket */
ptr = buffer_read_ptr(b, &avail);           /* dónde y cuánto hay para leer     */
n = send(fd, ptr, avail, 0);
buffer_read_adv(b, n);                      /* avanza el puntero de lectura     */
```

Los parsers consumen de a un byte con `buffer_read(b)`, y los predicados `buffer_can_read` / `buffer_can_write` deciden los intereses del selector: si no hay nada para leer no se pide `OP_WRITE` hacia el otro extremo, y si el buffer está lleno se deja de pedir `OP_READ` (contrapresión natural). Cuando `read == write` el buffer se auto-compacta (ambos punteros vuelven al inicio); también puede forzarse con `buffer_compact`, que corre los bytes pendientes al comienzo para recuperar espacio contiguo.

Es la pieza que sostiene tanto el parseo incremental del handshake como el relay full-duplex: cada conexión usa dos buffers, uno para el sentido `cliente → origen` y otro para `origen → cliente`.

### 11.4. Handler de conexión SOCKS5 (`socks5.c`)

Cada conexión SOCKS5 es una instancia de máquina de estados. Los estados reflejan directamente las fases del RFC 1928 más la resolución y el relay:

```c
enum socks5_state {
    NEG_READ,       /* negociación de métodos (parseo)          */
    NEG_WRITE,      /* respuesta de método (2 bytes)            */
    AUTH_READ,      /* credenciales user/pass (RFC 1929)        */
    AUTH_WRITE,     /* respuesta de auth (2 bytes)              */
    REQ_READ,       /* parseo del request                      */
    REQ_RESOLVE,    /* esperando resolución DNS (hilo aparte)  */
    REQ_CONNECTING, /* connect() no bloqueante en vuelo        */
    REQ_WRITE,      /* respuesta del request                   */
    RELAY,          /* relay full-duplex cliente ↔ origen      */
    DONE, ERROR,    /* estados terminales                      */
};
```

El estado por conexión (`struct socks5_conn`) agrupa la máquina de estados, los parsers de cada fase (negociación, auth, request), los dos buffers de relay, los descriptores de cliente y origen, y el manejo de referencias para el teardown (dos descriptores comparten un mismo `conn`, que se libera cuando ninguno queda registrado). El flujo típico es:

1. Negociación (`negotiation.c`): el cliente ofrece métodos, el servidor elige usuario/contraseña.
2. Autenticación (`auth.c`): se validan las credenciales contra el almacén de usuarios (RFC 1929).
3. Request (`request.c`): se parsea el `CONNECT` con destino IPv4, IPv6 o FQDN. Para un FQDN se pasa a `REQ_RESOLVE` (resolución en el pool de hilos); para una dirección literal se arma una entrada sintética sin resolver.
4. Conexión al origen: `connect(2)` no bloqueante, con reintento sobre las sucesivas direcciones que devolvió la resolución si alguna falla.
5. Relay: transferencia full-duplex hasta que ambos extremos cierran, con manejo de `shutdown` por sentido (half-close) y contabilización de bytes en cada dirección.

El registro de estados se declara como una tabla que el motor de `stm` recorre:

```c
static const struct state_definition socks5_states[] = {
    { .state = NEG_READ,   .on_arrival = negotiation_read_init, .on_read_ready = negotiation_read },
    { .state = NEG_WRITE,  .on_write_ready = negotiation_write },
    /* ... AUTH_READ, AUTH_WRITE, REQ_READ ... */
    { .state = REQ_RESOLVE,    .on_block_ready = request_resolve_done },
    { .state = REQ_CONNECTING, .on_write_ready = request_connecting },
    { .state = RELAY, .on_arrival = relay_init, .on_read_ready = relay_read, .on_write_ready = relay_write },
    /* DONE, ERROR */
};
```

### 11.5. Pool de resolución DNS

Es la única concurrencia real del servidor. Un pool acotado de 4 hilos (`RESOLVER_WORKERS`) toma trabajos de una cola protegida por mutex/condición y ejecuta el `getaddrinfo` bloqueante fuera del hilo del selector:

```c
#define RESOLVER_WORKERS 4
static pthread_mutex_t resolver_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  resolver_cond  = PTHREAD_COND_INITIALIZER;
static pthread_t       resolver_threads[RESOLVER_WORKERS];
```

Cuando el trabajo termina, el hilo escribe el resultado en el `conn` y notifica al selector con `selector_notify_block`; el evento `on_block_ready` reingresa la conexión al flujo (`request_resolve_done`) desde el hilo principal. Los trabajos pueden cancelarse (por ejemplo si la conexión se cierra antes de que la resolución termine), y el pool se detiene ordenadamente al apagar el servidor.

### 11.6. Estado runtime e inyección de dependencias

Varios módulos mantienen estado del proceso que vive en `main()` como almacenamiento estático y se inyecta en los componentes que lo consumen (mismo patrón `*set*` en todos):


| Módulo         | Responsabilidad                                                              |
| -------------- | ---------------------------------------------------------------------------- |
| `users.c`      | Almacén de usuarios del proxy, modificable en caliente vía SMCP.             |
| `config.c`     | Parámetros runtime (`conn_timeout`, `io_buffer_size`, `max_connections`).    |
| `metrics.c`    | Métricas volátiles (conexiones activas/históricas, pico, bytes por sentido). |
| `access_log.c` | Registro de accesos persistente en archivo (modo append).                    |


```c
socks5_set_users(&users);
socks5_set_metrics(&metrics);
socks5_set_access_log(&access_log);
socks5_set_config(&config);
mgmt_set_deps(&mgmt_deps);   /* users, metrics, config, access_log, admin */
```

Este diseño mantiene los módulos desacoplados y testeables sin red: las métricas y el registro se actualizan siempre desde el hilo del selector, por lo que no requieren locks ni atómicos.

### 11.7. Implementación del servicio de management

El servidor expone, en el mismo proceso y event loop pero en otro socket pasivo, el protocolo SMCP. La implementación separa el parseo/despacho (independiente de sockets, y por eso testeable de forma aislada) del pegamento con el selector:

- `mgmt_parser.c` — parser de línea reentrante (tolera lecturas parciales y pipelining, aplica el tope de longitud de línea).
- `mgmt.c` — convierte una línea de comando en una respuesta escrita a un buffer, gestiona la máquina de sesión `NO_AUTH → AUTH` y las credenciales de admin.

### 11.8. Infraestructura de soporte

- Parser genérico (`parser.c` / `parser_utils.c`): motor de parsing dirigido por tablas de transición, disponible en la infraestructura compartida. Las fases del handshake y SMCP usan parsers reentrantes propios, más simples y específicos de cada formato.
- Utilidades de red (`netutils.c`): helpers de sockets y direcciones.
- Argumentos (`args.c`): parseo de las opciones de línea de comandos.
- Cliente CLI (`src/client/`, `smcp_client.c`): habla SMCP para monitorear y configurar el servidor desde la línea de comandos.
- Pruebas unitarias (`test/`): batería con el framework Check, una por módulo.

---

## 12. Bibliografía

- RFC 1928 — SOCKS Protocol Version 5.
- RFC 1929 — Username/Password Authentication for SOCKS V5. 


