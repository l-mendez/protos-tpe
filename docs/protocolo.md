# Notas

No hace falta auth GSSAPI

Se puede usar un thread aparte para hacer la resolucion de nombres de domino

## TODO

- [ ] hacer que las metricas sea un adt
- [ ] single source of truth para el active connections (idealmente en el metrics)
- [ ] correrle un formatter
- [ ] hacer un docker para correrlo en linux
- [ ] revisar bien los requerimientos y como se tiene que probar
- [ ] Protocolo
- [ ] cliente


## Decisiones del protocolo

transporte: tcp
(entiendo que un admin que quiere ver metricas se va a quedar conectado un rato)

de texto para primero poder probarlo con netcat y mas facil de debuggear

ha que definir un fin de linea (podria ser simplemente un \n) tratando de dejarlo
lo mas simple posible

¡