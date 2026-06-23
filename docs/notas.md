# Sockets

Es un fd.

Hay varios tipos de sockets, por ejemplo el `AF_INET` (son los que vamos a usar).

- Usamos `seesockopt` para setear las flags.
- El flag de `SO_REUSEADDR`.
- `fcntl` es para setear flags en los fd. Con el flag de `O_NONBLOCK` podemos hacer que sea no bloqueante.

## Indicaciones / tips

- Después de hacer la versión i/o, agarrar el selector o el pollinator y hacer un echo server así, con máquina de estados; porque si primero hacemos uno bloqueante después va a ser muy difícil pasar.
- Estaría bueno manejar señales como el `Ctrl+C` y cerrar limpiamente las conexiones, o tipo no aceptar conexiones nuevas pero no cortar las conexiones que estás manejando ahora.
- Hay que usar `accept` en el socket pasivo.
- Cuidado con cómo hacemos la lectura: tenemos que poder manejar Auth, Req, Data cuando nos lo mandan todo junto como si nos lo hubiesen mandado por separado (pipelining) → el servidor tiene que llevar el estado.

> [!note]
> *Pipelining*: que se puedan mandar varias requests seguidas sin esperar respuestas en el medio.

- Ir escribiendo un `.md` con las decisiones que vamos tomando para después incluir en el informe.
- Unas buenas justificaciones para decisiones puede ser:
	- Nunca lo hicimos y queríamos probar.
	- Porque es más fácil de implementar / tiene menos overhead.
- Definir el *"endianness"* de los protocolos.

## Secuencia de objetivos

1. Hacer algo simple sincrónico con sockets que maneje de a un cliente a la vez con el protocolo sock5.
2. Hacer un echo server pero que maneje varios clientes con el selector o pollinator.
3. Ahora sí nos metemos en máquinas de estado, sock5 y el tp en general.

## Recursos piolas

- https://github.com/ThomasMiz/pollinator
