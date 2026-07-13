# Protocolo de Monitoreo y Configuración de SOCKS5 (SMCP)

**SOCKS5 Management & Configuration Protocol**
Versión 1.0 — ITBA, Protocolos de Comunicación 2026/1

## Abstract

Este documento especifica SMCP, un protocolo de aplicación para monitorear y
administrar en tiempo de ejecución un servidor proxy SOCKS5. SMCP permite a un
administrador consultar métricas de operación, gestionar los usuarios del proxy,
modificar parámetros de configuración sin reiniciar el servidor y consultar el
registro de accesos.

SMCP es un protocolo **independiente** de SOCKS v5 (RFC 1928): escucha en un
socket pasivo y puerto propios, dentro del mismo proceso servidor.

## 1. Terminología

Las palabras clave "DEBE", "NO DEBE", "OBLIGATORIO", "DEBERÁ", "NO DEBERÁ",
"DEBERÍA", "NO DEBERÍA", "RECOMENDADO", "PUEDE" y "OPCIONAL" en este documento
serán interpretadas como se describe en el RFC 2119.

- **Cliente**: la aplicación de administración que inicia la conexión SMCP.
- **Servidor**: el proceso proxy SOCKS5 que expone el socket SMCP.
- **Sesión**: la conexión TCP entre cliente y servidor, desde su apertura hasta
  su cierre.
- **Usuario del proxy**: una credencial usuario/contraseña aceptada por el
  servicio SOCKS5 (RFC 1929). SMCP administra este conjunto.
- **Administrador**: la credencial usuario/contraseña que autoriza el uso de
  SMCP. Es **distinta** del conjunto de usuarios del proxy.

## 2. Modelo de transporte y de sesión

### 2.1. Transporte

SMCP se transporta sobre **TCP**. El servidor DEBE escuchar en una dirección y
puerto configurables (por defecto `127.0.0.1:8080`), independientes de los del
servicio SOCKS5.

### 2.2. Sesión

Una sesión es **persistente y con estado**: el cliente abre una conexión, emite
uno o más comandos de forma secuencial y la cierra con `QUIT`. El servidor DEBE
procesar los comandos de una sesión en el orden en que llegan y responder en ese
mismo orden (un comando, una respuesta).

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

- **NO_AUTH**: estado inicial. El servidor SÓLO DEBE aceptar los comandos
  `AUTH`, `HELP` y `QUIT`. Cualquier otro comando DEBE responder
  `-ERR not authenticated`.
- **AUTH**: alcanzado tras un `AUTH` exitoso. Todos los comandos están
  disponibles.

El servidor DEBE atender las sesiones SMCP de forma no bloqueante.

## 3. Formato de los mensajes

### 3.1. Marco (framing)

SMCP es un protocolo **de texto orientado a líneas**.

- Tanto los comandos (cliente → servidor) como las líneas de respuesta
  (servidor → cliente) terminan con el carácter **LF** (`0x0A`, `\n`).
- Un `CR` (`0x0D`) inmediatamente anterior al `LF` DEBE ser tolerado y
  descartado. El cliente DEBERÍA enviar sólo `LF`.
- Una línea NO DEBE exceder los **4096 bytes** incluyendo el terminador. Si el
  servidor recibe una línea más larga, DEBE responder `-ERR line too long` y
  descartar los bytes hasta el próximo `LF`.
- La codificación es ASCII de 7 bits. Los bytes fuera de `0x20`–`0x7E` (salvo el
  terminador) en un comando producen `-ERR invalid`.

Tanto cliente como servidor DEBEN tolerar lecturas y escrituras parciales: un
comando o una respuesta pueden llegar fragmentados en varios segmentos TCP, o
varios comandos pueden llegar en un mismo segmento (pipelining). El parseo DEBE
ser reentrante y conservar el progreso entre lecturas.

### 3.2. Sintaxis de un comando

```
comando   = palabra *( SP argumento ) LF
palabra   = 1*(ALPHA / "-")
argumento = 1*(VCHAR)
SP        = %x20
```

- La **palabra de comando** es *case-insensitive* (`METRICS`, `metrics` y
  `Metrics` son equivalentes). Los argumentos son *case-sensitive*.
- Los argumentos se separan por **un** espacio. Por lo tanto, nombres de usuario
  y contraseñas creados vía SMCP **NO PUEDEN contener espacios**.
- El número de argumentos es fijo por comando (ver Sección 4). Argumentos de más
  o de menos producen `-ERR invalid`.

### 3.3. Sintaxis de una respuesta

Toda respuesta comienza con una **línea de estado**:

```
estado = ("+OK" / "-ERR") [ SP texto ] LF
```

- `+OK` indica éxito; `-ERR` indica error. El `texto` es informativo y legible.
- Las respuestas de **enumeración** (listas de pares clave/valor o de registros)
  usan marco **prefijado por cantidad**: la línea de estado es `+OK <n>`, donde
  `<n>` es un entero decimal, y a continuación siguen **exactamente `<n>`
  líneas** de datos. No hay línea terminadora ni *dot-stuffing*.

  ```
  +OK 3
  active_connections 12
  historical_connections 4033
  total_bytes 8823123
  ```

  Los nombres de clave usan `snake_case`.

## 4. Comandos

En las descripciones, `<x>` es un argumento obligatorio y `[x]` uno opcional.

| Comando | Estado requerido | Descripción |
|---------|------------------|-------------|
| `AUTH <usuario> <contraseña>` | `NO_AUTH` | Autentica al administrador y habilita los comandos privilegiados de la sesión. |
| `METRICS` | `AUTH` | Devuelve métricas actuales del proxy, como conexiones activas, histórico de conexiones, bytes transferidos y cantidad de usuarios. |
| `LIST-USERS` | `AUTH` | Lista los nombres de usuarios habilitados para autenticarse contra el proxy SOCKS5. |
| `ADD-USER <usuario> <contraseña>` | `AUTH` | Agrega una credencial de usuario del proxy, efectiva para nuevas conexiones SOCKS5. |
| `DEL-USER <usuario>` | `AUTH` | Elimina una credencial de usuario del proxy sin cerrar conexiones ya establecidas. |
| `GET-CONFIG` | `AUTH` | Devuelve los parámetros de configuración modificables en tiempo de ejecución. |
| `SET <clave> <valor>` | `AUTH` | Modifica un parámetro de configuración válido, respetando el rango definido para esa clave. |
| `LOG [n]` | `AUTH` | Devuelve los últimos registros de acceso, del más reciente al más antiguo. |
| `PASSWD <nueva-contraseña>` | `AUTH` | Cambia la contraseña del administrador para nuevas sesiones. |
| `HELP` | cualquiera | Devuelve la lista de comandos disponibles. |
| `QUIT` | cualquiera | Cierra la sesión SMCP de forma ordenada. |

### 4.1. AUTH — autenticación

```
AUTH <usuario> <contraseña>
```

Autentica al administrador. DEBE ser el primer comando de toda sesión que
requiera operaciones privilegiadas. En caso de éxito la sesión pasa al estado
AUTH.

- Éxito: `+OK authenticated`
- Credenciales inválidas: `-ERR bad credentials`
- Ya autenticado: `-ERR already authenticated`

El servidor NO DEBE revelar si el fallo se debió al usuario o a la contraseña.

### 4.2. METRICS — métricas de operación

```
METRICS
```

Devuelve las métricas actuales como pares `clave valor` (una por línea). Los
valores son enteros decimales no negativos. Ver Sección 5.

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

### 4.3. LIST-USERS — listar usuarios del proxy

```
LIST-USERS
```

Devuelve los nombres de los usuarios del proxy, uno por línea. Las contraseñas **NUNCA** se devuelven.

```
+OK 2
pablito
juana
```

### 4.4. ADD-USER — alta de usuario del proxy

```
ADD-USER <usuario> <contraseña>
```

Da de alta un usuario del proxy. El cambio tiene efecto inmediato: nuevas
conexiones SOCKS5 podrán autenticarse con esa credencial.

- Éxito: `+OK user added`
- Ya existe: `-ERR user exists`
- Límite alcanzado: `-ERR store full`
- Usuario/contraseña vacío, con espacios o demasiado largo (> 255 bytes):
  `-ERR invalid`

### 4.5. DEL-USER — baja de usuario del proxy

```
DEL-USER <usuario>
```

Elimina un usuario del proxy. Las conexiones SOCKS5 ya establecidas por ese
usuario NO se cierran; sólo se impiden nuevas autenticaciones.

- Éxito: `+OK user removed`
- No existe: `-ERR no such user`

### 4.6. GET-CONFIG — leer configuración

```
GET-CONFIG
```

Devuelve los parámetros de configuración modificables como pares `clave valor`.
Ver Sección 6.

```
+OK 3
conn_timeout 60
io_buffer_size 4096
max_connections 500
```

### 4.7. SET — modificar configuración

```
SET <clave> <valor>
```

Modifica un parámetro de configuración en tiempo de ejecución. Ver Sección 6
para las claves válidas, sus rangos y su semántica.

- Éxito: `+OK <clave> = <valor>`
- Clave desconocida: `-ERR unknown key`
- Valor fuera de rango o mal formado: `-ERR invalid value`

### 4.8. LOG — consultar registro de accesos

```
LOG [n]
```

Devuelve los últimos `n` registros de acceso, del más reciente al más antiguo.
Si se omite `n`, el servidor DEBE usar un valor por defecto (RECOMENDADO: 10). Si
`n` excede la cantidad de registros almacenados, se devuelven todos los
disponibles. Ver Sección 7 para el formato de cada registro.

```
+OK 2
2026-07-09T14:22:07Z pablito CONNECT 1.2.3.4:80 CONN-REFUSED
2026-07-09T14:22:01Z pablito CONNECT example.com:443 OK
```

### 4.9. PASSWD — cambiar contraseña del administrador

```
PASSWD <nueva-contraseña>
```

Cambia la contraseña del administrador de la sesión actual. Tiene efecto
inmediato para nuevas sesiones; la sesión en curso permanece autenticada.

- Éxito: `+OK password changed`
- Contraseña vacía, con espacios o demasiado larga: `-ERR invalid`

### 4.10. HELP — ayuda

```
HELP
```

Devuelve la lista de comandos disponibles, uno por línea. Disponible en
cualquier estado.

### 4.11. QUIT — cerrar sesión

```
QUIT
```

Cierra la sesión de forma ordenada. El servidor responde `+OK bye` y luego
cierra la conexión. Disponible en cualquier estado.

## 5. Métricas

El servidor DEBE exponer al menos las siguientes métricas. Las métricas son
volátiles: se reinician al reiniciar el servidor.

| Clave                     | Tipo | Descripción                                                   |
|---------------------------|------|---------------------------------------------------------------|
| `active_connections`      | u64  | Conexiones SOCKS5 activas en este instante.                   |
| `historical_connections`  | u64  | Conexiones SOCKS5 aceptadas desde el arranque.                |
| `max_active_connections`  | u64  | Pico histórico de conexiones concurrentes.                    |
| `bytes_client_to_origin`  | u64  | Bytes relayados de cliente a origen.                          |
| `bytes_origin_to_client`  | u64  | Bytes relayados de origen a cliente.                          |
| `total_bytes`             | u64  | Suma de ambas direcciones.                                    |
| `users_count`             | u64  | Cantidad de usuarios del proxy configurados actualmente.      |

Una implementación PUEDE exponer pares `clave valor` adicionales; el cliente
DEBE tolerar claves que no conozca.

## 6. Configuración

Claves aceptadas por `SET`/`GET-CONFIG`:

| Clave             | Tipo   | Rango                | Semántica                                                                                 |
|-------------------|--------|----------------------|-------------------------------------------------------------------------------------------|
| `conn_timeout`    | u32    | 1 .. 3600 (segundos) | Tiempo de inactividad tras el cual una conexión SOCKS5 se cierra. Afecta a todas.         |
| `max_connections` | u32    | 1 .. límite duro     | Tope de conexiones SOCKS5 concurrentes. Se aplica como límite blando al aceptar.          |
| `io_buffer_size`  | u32    | 512 .. 65536 (bytes) | Tamaño del buffer de relay por conexión. Sólo afecta a **conexiones nuevas**.             |

Notas de semántica:

- `max_connections` sólo puede **reducirse** por debajo del límite duro derivado
  de la capacidad del multiplexor. El cálculo contempla dos descriptores por
  túnel y reserva espacio para listeners y management. Al reducirlo, las
  conexiones existentes NO se cierran; sólo se rechazan nuevas por encima del
  tope.
- `io_buffer_size` NO DEBE alterar los buffers de conexiones ya establecidas.

## 7. Registro de accesos

Cada registro de acceso describe un intento de conexión de un usuario del proxy a
un destino. A diferencia de las métricas (que PUEDEN ser volátiles), el registro
de accesos DEBE ser **persistente**: el servidor lo escribe, una línea por
intento de conexión, en un **archivo de texto** en modo *append* (su ruta se
configura al iniciar el servidor).

El comando `LOG [n]` (Sección 4.8) devuelve las últimas `n` líneas de ese
archivo como vista de conveniencia sobre el protocolo; el archivo sigue siendo la
fuente de verdad.

Formato de un registro (una línea, idéntico en el archivo y en la respuesta a
`LOG`):

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

## 8. Códigos y mensajes de error

Todo error se reporta con una línea `-ERR <texto>`. Los errores específicos de
cada comando se documentan en la Sección 4. Los siguientes son transversales a
todos los comandos:

| Texto               | Situación                                       |
|---------------------|-------------------------------------------------|
| `not authenticated` | Comando privilegiado en estado NO_AUTH.         |
| `unknown command`   | Palabra de comando no reconocida.               |
| `invalid`           | Cantidad o forma de argumentos inválida.        |
| `line too long`     | Línea que excede 4096 bytes.                     |

## 9. Consideraciones de seguridad

- Las credenciales viajan **en texto plano**. SMCP DEBERÍA escuchar sólo en
  `127.0.0.1` (interfaz de loopback) por defecto; exponerlo en una interfaz de
  red requiere un canal seguro externo (p.ej. un túnel SSH).
- El servidor NO DEBE distinguir en la respuesta entre "usuario inexistente" y
  "contraseña incorrecta" durante `AUTH`.
- El límite de longitud de línea (Sección 3.1) acota el consumo de memoria por
  sesión y previene ataques de agotamiento.

## 10. Ejemplo de sesión completa

```
C: (abre conexión TCP a 127.0.0.1:8080)
S: +OK SMCP 1.0 ready
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

Nota: el servidor PUEDE enviar una línea de saludo `+OK SMCP 1.0 ready` al
aceptar la conexión. El cliente DEBE tolerar su presencia o ausencia.
