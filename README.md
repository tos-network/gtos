## Terminos Network

Official Golang implementation of the TOS Network Protocol.

## Building the source

Building `gtos` requires both a Go (version 1.22 or later) and a C compiler. You can install
them using your favourite package manager. Once the dependencies are installed, run

```shell
make gtos
```

or, to build the full suite of utilities:

```shell
make all
```

## License

The gtos library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The gtos binaries (i.e. all code inside of the `cmd` directory) is licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
