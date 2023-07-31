# gwcert

[![PyPI](https://img.shields.io/pypi/v/gridworks-cert.svg)][pypi_]
[![Status](https://img.shields.io/pypi/status/gridworks-cert.svg)][status]
[![Python Version](https://img.shields.io/pypi/pyversions/gridworks-cert)][python version]
[![License](https://img.shields.io/pypi/l/gridworks-cert)][license]

[![Read the documentation at https://gridworks-cert.readthedocs.io/](https://img.shields.io/readthedocs/gridworks-cert/latest.svg?label=Read%20the%20Docs)][read the docs]
[![Tests](https://github.com/thegridelectric/gridworks-cert/workflows/Tests/badge.svg)][tests]
[![Codecov](https://codecov.io/gh/thegridelectric/gridworks-cert/branch/main/graph/badge.svg)][codecov]

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)][pre-commit]
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)][black]

Tools for creating TLS certificates for use with, e.g. MQTT and RabbitMQ.

**NOTE**: these are temporary tools for _non-production_ deployments. This library is more or less equivalent to a README
containing [OpenSSL] commands, but less manual.

This library is a thin wrapper around [ownca], which wraps [pyca/cryptography], which wraps the [OpenSSL] C library.
See also [tls-gen], a repo from [rabbitmq], which performs a similar task using a stack of make/python/OpenSSL CLI.

## Features

- Create a local Certificate Authority directory with a self-signed certificate, via `gwcert ca create`.
- Create named key pairs, CSRs and certificates with _arbitrary_ input and output paths, via `gwcert key add`.
- Build cli commands visually with `gwcert tui`.

## Installation

The recommended way to install _gwcert_ is with [pipx] from [PyPI]:

```console
$ pipx install gridworks-cert
```

## Usage

Get help with any of:

```shell
gwcert
gwcert ca
gwcert key
```

Create a Certificate Authority directory with a self-signed certificate via:

```shell
gwcert ca create
```

Show information about the locally created ca and keys with:

```shell
gwcert ca info
```

Add a named set of keys (public, private, certificate) via, for example:

```shell
gwcert key add KEY_NAME
```

Show information about a certificate:

```shell
gwcert key info KEY_NAME
```

Build CLI commands visually:

```shell
gwcert tui
```

Please see the [Command-line Reference] for more details.

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [MIT license][license],
_gwcert_ is free and open source software.

## Issues

If you encounter any problems,
please [file an issue] along with a detailed description.

## Credits

This project was generated from [@cjolowicz]'s [Hypermodern Python Cookiecutter] template.

[@cjolowicz]: https://github.com/cjolowicz
[pypi]: https://pypi.org/
[hypermodern python cookiecutter]: https://github.com/cjolowicz/cookiecutter-hypermodern-python
[file an issue]: https://github.com/thegridelectric/gridworks-cert/issues
[pip]: https://pip.pypa.io/
[pypi_]: https://pypi.org/project/gridworks-cert/
[status]: https://pypi.org/project/gridworks-cert/
[python version]: https://pypi.org/project/gridworks-cert
[read the docs]: https://gridworks-cert.readthedocs.io/
[tests]: https://github.com/thegridelectric/gridworks-cert/actions?workflow=Tests
[codecov]: https://app.codecov.io/gh/thegridelectric/gridworks-cert
[pre-commit]: https://github.com/pre-commit/pre-commit
[black]: https://github.com/psf/black
[tls-gen]: https://github.com/rabbitmq/tls-gen
[ownca]: https://ownca.readthedocs.io/en/latest/
[pyca/cryptography]: https://cryptography.io/en/latest/
[openssl]: https://www.openssl.org/
[rabbitmq]: https://rabbitmq.com/ssl.html#automated-certificate-generation-transcript
[pipx]: https://pypa.github.io/pipx/

<!-- github-only -->

[license]: https://github.com/thegridelectric/gridworks-cert/blob/main/LICENSE
[contributor guide]: https://github.com/thegridelectric/gridworks-cert/blob/main/CONTRIBUTING.md
[command-line reference]: https://gridworks-cert.readthedocs.io/en/latest/usage.html
