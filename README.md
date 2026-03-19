## TS 103 744 Quantum-safe Hybrid Key Exchanges ##

Informative reference implementation as reported in Annex C of ETSI TS 103 744,
"CYBER; Quantum-safe Hybrid Key Exchanges". The code is not intended for production use.
It is intended to be a reference implementation for test vector generation.

More information and standards download at the [work item page](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=56901).

### Usage ###

This code is provided as an informative implementation of the Quantum-safe Hybrid Key Exchanges for the Concatenate
KDF (CatKDF) and Cascade KDF (CasKDF). It generates the test vectors contained in the TS.

This is not intended for production use. It is intended to be a reference
implementation for test vectors for the specification.

### Prerequisites ###

- GCC compiler
- GNU Make
- OpenSSL 3.2 (cloned and built automatically by the Makefile)
- [liboqs](https://github.com/open-quantum-safe/liboqs) v0.13.0 (cloned and built automatically)
- [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) v0.7.0 (cloned and built automatically)

On Linux, the following packages are required and will be installed by `make`:
`git`, `build-essential`, `perl`, `cmake`, `autoconf`, `libtool`, `zlib1g-dev`

### Build instructions ###

To clone and build all dependencies (OpenSSL, liboqs, and oqs-provider), compile, and run:

    make

To build and run etsi-hkex-test only (after dependencies are built):

    make run

Or compile manually (with appropriate include and library paths):

    gcc -Wall -o etsi-hkex-test main.c crypto.c qshkex.c -lcrypto -loqs
    ./etsi-hkex-test

### Repository ###

Source code is hosted at the ETSI forge:

    git clone https://forge.etsi.org/rep/cyber/103744_QHKEX.git

### License ###

The content of this repository and the files
contained are released under the BSD-3-Clause license.
See the attached LICENSE file or visit https://forge.etsi.org/legal-matters.
