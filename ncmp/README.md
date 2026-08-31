# Token NCMP subsystem

Self-contained CMake tree for the NCMP PKCS#11 token added to this opencryptoki
fork: the `ncmpd` daemon, the `libpkcs11_ncmp.so` STDLL, a software mock token,
and a test suite. See [`../CLAUDE.md`](../CLAUDE.md) for rules and
[`../docs/architecture.md`](../docs/architecture.md) for the full design.

## Build

```bash
cmake -S . -B build -DENABLE_MOCK_TOKEN=ON   # mock: no hardware/libusb needed
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Omit `-DENABLE_MOCK_TOKEN` to build the real-hardware path (needs libusb-1.0).

## Layout

- `include/ncmp/` — shared public headers (limits, wire, queue, shm, mutex, ipc)
- `common/` — shared primitives (robust mutex, CAS queue, wire, shm)
- `daemon/` — Module A: `ncmpd`
- `stdll/` — Module B: `libpkcs11_ncmp.so`
- `mock/` — Module C: `mock_token_ncmp`
- `tests/` — Module D: ctest suite
- `cmake/` — `FindLibUSB.cmake`

## Status

Scaffold: headers and build system are complete and compile clean; `.c` units
carry Doxygen contracts with `TODO` bodies where hardware/daemon runtime is
still to be implemented. Unit tests for wire limits, CAS queue transitions, and
session ceilings are functional and pass today.
