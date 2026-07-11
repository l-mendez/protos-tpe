# TODO

- [x] add `-a` arg
- [x] agregar metricas necesarias
- [x] Refactor para run-time configuration (de algunas cosas)
- [x] hacer un parser para el protocolo smcp
- [x] maquina de estados para el smcp
- [x] integrarlo con `main.c` abriendo un socket mas
- [x] hacer el cliente

## Despues

- [ ] ver si hacer El coso que maneja usuarios un adt (o en general hacer las cosas adts)
- [ ] ver si queremos devolver el indice o un usuario
- [ ] revisar `sock5.c` que quedo de como 1400 lineas (ver si se puede modularizar un poco mas)
- [ ] por ahi organizarlo mejor en carpetas tipo `include` para los .h o tambien carpeta aparte para los adts? ver si eso tiene sentido
- [ ] hacer el parser un adt para reutilizarlo tanto en el cliente como en main