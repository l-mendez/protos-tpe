
# Sockets

Es un fd

Hay varios tipos de sockets, por ejemplo el `AF_INET` (son los que vamos a usar)

usamos `seesockopt` para setear las flags

El flag de `SO_REUSEADDR` 

`fcntl` es para setear flags en los fd. con el flag de `O_NONBLOCK` podemos hacer que sea no bloqueante

## Indicaciones/tips

Despues de hacer la version i/o, agarrar el selector o el pollinator y hacer un echo server asi, con maquina de estados porque si primero hacemo uno bloqueante despues va a ser muy dificil pasar

Estaria bueno manejar señales como el ctrl+c y cerrar limpiamente las conexiones o tipo no aceptar conexiones nuevas pero no cortas las conexiones que estas manejando ahora

Hay que usar `accept` en el socket pasivo

cuidado con como hacemos la lectura, tenemos que poder manejar Auth, Req, Data cuando nos lo mandan todo junto como si nos lo hubiesen mandado por separado. (pipelining) -> el servidor tiene que llevar el estado)

>[!note]
>*Pipelining*: que se puedan mandar varias requests seguidas sin esperar respuestas en el medio

Ir escribiendo un  md con las decisiones que vamos tomando para desues incluir en el informe

Unas buenas justificacion para decisiones puede ser:
- Nunca lo hicimos y queriamos probar
- porque es mas facil de implementar / tiene menos overhead

definir el *"endianness"* de los protocolos
## Secuencia de objetivos

1. Hacer algo simple sincronico con sockets que maneje de aun cliente a la vez con el protocolo sock5. 
2. Hacer un echo server pero que maneje varios clientes con el selector o pollinator
3. Ahora si nos metemos en maquinas de estado, sock5 y el tp en general

## Recursos piolas

- https://github.com/ThomasMiz/pollinator

