# Proxy SOCKS5

Servidor proxy para el protocolo SOCKS versión 5 ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928))
con autenticación usuario/contraseña ([RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929)),
junto con un protocolo propio de monitoreo y configuración en caliente y su cliente
de línea de comandos.

## Requisitos

- `gcc` con soporte para C11.
- `make`.
- [Check](https://libcheck.github.io/check/) (opcional, sólo para `make test`).

## Compilación

```sh
make            # compila servidor y cliente
make server     # sólo el servidor
make client     # sólo el cliente
make clean      # elimina los artefactos generados
```

## Artefactos

| Artefacto      | Descripción                                  |
| -------------- | -------------------------------------------- |
| `bin/server`   | servidor proxy SOCKS5 y servicio de management |
| `bin/client`   | cliente de monitoreo y configuración          |

Los objetos intermedios se generan bajo `obj/`.

## Ejecución

```sh
./bin/server [OPCIÓN]...
```

| Opción              | Descripción                                                        | Default       |
| ------------------- | ------------------------------------------------------------------ | ------------- |
| `-l <dirección>`    | dirección de escucha del proxy SOCKS                               | `0.0.0.0`     |
| `-p <puerto>`       | puerto de escucha del proxy SOCKS                                  | `1080`        |
| `-L <dirección>`    | dirección de escucha del servicio de management                   | `127.0.0.1`   |
| `-P <puerto>`       | puerto de escucha del servicio de management                      | `8080`        |
| `-u <usr>:<pass>`   | credencial habilitada para el proxy (hasta 10 veces)              | —             |
| `-h`                | imprime la ayuda y termina                                        | —             |
| `-v`                | imprime la versión y termina                                      | —             |

## Pruebas

```sh
make test       # compila y ejecuta la batería de pruebas unitarias
```

## Estructura

```
src/shared/   utilidades comunes al servidor y al cliente
src/server/   servidor proxy SOCKS5 y servicio de management
src/client/   cliente de monitoreo y configuración
test/         pruebas unitarias
```
