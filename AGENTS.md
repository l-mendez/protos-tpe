# Repository Guidelines

## Project Structure & Module Organization

This repository implements a SOCKS5 proxy server and a command-line management client in C.

- `src/server/`: SOCKS5 server, authentication, negotiation, request handling, and server loop.
- `src/client/`: command-line client entry point.
- `src/shared/`: reusable utilities shared by server, client, and tests, including buffers, parser helpers, selector, state machines, args, and network utilities.
- `test/`: unit tests, named `*_test.c`, plus small test assets such as `foo.dot`.
- `docs/`: project notes and supporting documentation.
- `bin/` and `obj/`: generated build artifacts; do not commit them.

## Build, Test, and Development Commands

- `make`: builds both `bin/server` and `bin/client`.
- `make server`: builds only the SOCKS5 server.
- `make client`: builds only the management client.
- `make test`: builds every `test/*_test.c` binary under `bin/test/` and runs the full suite.
- `make clean`: removes `bin/` and `obj/`.

The build uses `gcc`, C11, pthreads, and flags from `Makefile.inc`. Tests require the Check framework; `pkg-config` is used when available.

## Coding Style & Naming Conventions

Use C11 and keep code compatible with the existing warning profile: `-Wall -Wextra -pedantic`. Prefer small C modules with matching headers, for example `src/server/auth.c` and `src/server/auth.h`.

Follow the existing style: 4-space indentation, braces on their own line for function definitions, compact struct initializers, and `snake_case` for functions, variables, files, and test names. Keep comments useful and concise; Spanish comments already exist, so either Spanish or English is acceptable, but stay consistent within the touched area.

## Testing Guidelines

Tests use Check (`#include <check.h>`) and the `START_TEST` / `END_TEST` pattern. Add new tests under `test/` with the suffix `_test.c`, and name test cases after the behavior under test, for example `test_auth_rejects_bad_password`.

Some tests include implementation `.c` files directly to reach internal static functions. If you change internals in `src/server/` or `src/shared/`, run `make test` before submitting.

## Commit & Pull Request Guidelines

Recent history mixes merge commits with Conventional Commit-style messages such as `fix(socks5): ...` and `test(socks5): ...`. Prefer that format for new commits: `type(scope): concise imperative summary`.

Pull requests should include a short description, the affected module (`server`, `client`, `shared`, or `test`), linked issue when applicable, and the commands run for verification. Include logs or screenshots only when they clarify runtime behavior.

## Agent-Specific Instructions

Keep generated artifacts out of commits. Before editing, inspect nearby code and preserve local patterns. For behavioral changes, update or add focused tests in the same PR.
