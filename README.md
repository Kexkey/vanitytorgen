# Vanity Tor keys/onion addresses generator

## Assumptions

You know what you are doing.  You know where to copy the output files.
You know how to set up a Hidden Service.

Notes: finding a vanity address can take a lot of time.  The longer
the wanted prefix is, the more time it will take until it finds a match.
Expect to wait several thousands years for a 10+ character prefix.


## Prerequisites

- Docker is correctly installed
- You know what you are doing


## Build Docker image

```shell
docker build -t vanitytorgen .
```


## Docker image Usage

Once built, you can use the image like this:

```shell
docker run --rm -v "$PWD:/vanitytorgen" vanitytorgen prefix /vanitytorgen
```

When found, the output files will be found in the current directory.


## Executable Usage

Usage: vanitytorgen <prefix> [path]

Will generate Tor keys until corresponding onion address starts with <prefix>
When found, `hs_ed25519_secret_key`, `hs_ed25519_public_key` and
`hostname` files will be created in the given path location or
in current directory if path is not supplied.

