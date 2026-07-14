# Probar el proxy SOCKS5 con `curl`

Guía corta para verificar el servidor con `curl`. Todos los ejemplos asumen que
el proxy escucha en `127.0.0.1:1080` (default). Ajustá host y puerto si lo
arrancaste con `-l` / `-p`.

## Prueba rápida con autenticación

Terminal 1:

```sh
make
./bin/server -u pablito:pass1234 -a admin:s3cret -o access.log
```

Terminal 2:

```sh
# OK: el proxy resuelve el dominio
curl -x socks5h://pablito:pass1234@127.0.0.1:1080 https://example.com/

# OK: curl resuelve localmente y el proxy recibe una IP
curl -x socks5://pablito:pass1234@127.0.0.1:1080 https://example.com/

# Falla esperada: contraseña incorrecta
curl -x socks5h://pablito:incorrecta@127.0.0.1:1080 https://example.com/

# Falla esperada: destino local sin servicio; debe quedar registrado en access.log
curl -x socks5h://pablito:pass1234@127.0.0.1:1080 http://127.0.0.1:9/
tail -1 access.log
```

Para consultar métricas, usuarios, configuración y logs:

```sh
./bin/client -a admin:s3cret
```

## Prueba rápida sin autenticación

Terminal 1:

```sh
./bin/server
```

Terminal 2:

```sh
curl -x socks5h://127.0.0.1:1080 https://example.com/
curl -x socks5://127.0.0.1:1080 https://example.com/
```

## Comportamiento de autenticación (importante)

El modo de autenticación **lo fija cómo arrancaste el servidor**, no `curl`:

| Servidor arrancado con... | Método aceptado | Consecuencia |
| ------------------------- | --------------- | ------------ |
| al menos un `-u usr:pass` | **sólo** user/pass (RFC 1929) | conectarse sin credenciales **falla** |
| ningún `-u`               | **sólo** no-auth              | pasar credenciales es inútil (igual conecta sin ellas) |

O sea: no podés "conectar sin usuario" contra un servidor que tiene usuarios
cargados, ni autenticar contra uno que no los tiene. Para probar los dos
caminos hay que levantar el servidor de dos formas distintas.

## `socks5` vs `socks5h` (¿quién resuelve el DNS?)

`curl` ofrece dos variantes, y son la diferencia clave a la hora de probar:

| Forma en `curl`         | Alias con `-x`        | Quién resuelve el hostname | ATYP enviado al proxy |
| ----------------------- | --------------------- | -------------------------- | --------------------- |
| `--socks5 host:port`    | `-x socks5://host:port`  | **curl** (local)        | IPv4 / IPv6           |
| `--socks5-hostname h:p` | `-x socks5h://host:port` | **el proxy** (remoto)   | dominio               |

La `h` de `socks5h` = "resuelve el **h**ostname en el proxy". Es la que ejercita
el resolver del servidor y el tipo de dirección "dominio" del RFC 1928.

---

## Variantes útiles

Credenciales separadas de la URL:

```sh
curl --socks5-hostname 127.0.0.1:1080 --proxy-user pablito:pass1234 https://example.com/
```

Sin credenciales contra un servidor arrancado con `-u` debe fallar:

```sh
curl -x socks5h://127.0.0.1:1080 https://example.com
```

Forzar una IP literal:

```sh
curl -x socks5://pablito:pass1234@127.0.0.1:1080 http://93.184.216.34/
```

IPv6 literal, si el servidor tiene salida IPv6:

```sh
curl -6 -x socks5://pablito:pass1234@127.0.0.1:1080 "http://[2606:2800:220:1:248:1893:25c8:1946]/"
```

## Diagnóstico

```sh
# -v muestra la negociación del proxy y el handshake TLS
curl -v -x socks5h://pablito:pass1234@127.0.0.1:1080 https://example.com/

# sólo el código HTTP, para scripts
curl -s -o /dev/null -w '%{http_code}\n' -x socks5h://pablito:pass1234@127.0.0.1:1080 https://example.com/
```

## Resultados esperados

- **OK**: `curl` devuelve el cuerpo de la página y un código HTTP 2xx/3xx.
- **`Unable to receive initial SOCKS5 response` / `User was rejected`**:
  desajuste de autenticación (ver la tabla de la sección de autenticación).
- **`Can't complete SOCKS5 connection`**: el destino no respondió (DNS falló en
  el proxy, host inalcanzable o sin salida IPv6 para el caso IPv6).
