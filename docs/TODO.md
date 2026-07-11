# TODO

- [ ] ver de hacer todos los modulos adts por consistencia y porque extraño pi
- [ ] ver si queremos devolver el indice o un usuario en `users_find`
- [ ] revisar `sock5.c` que quedo de como 1500 lineas (ver si se puede modularizar un poco mas)
- [ ] por ahi organizarlo mejor en carpetas tipo `include` para los .h o tambien carpeta aparte para los adts? ver si eso tiene sentido
- [ ] hacer un adt `arg_parser` para reutilizarlo en el cliente y en el servidor, podemos mantener el `arg.c` pero que este llame al parser por atras (agrega mas codigo boiler plate pero me parece mejor para modularizar)