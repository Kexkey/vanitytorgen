# Vanity Tor key/onion address generator

## Assumptions

You know what you are doing.

Note: finding a vanity address can take a lot of time.  The longer
the prefix is, the more time it will take to find a match.
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

When found, the output files will be saved in the mounted directory.


## Executable Usage

Usage: `vanitytorgen <prefix> [path]`

Will generate Tor keys until corresponding onion address starts with <prefix>
When found, `hs_ed25519_secret_key`, `hs_ed25519_public_key` and
`hostname` files will be created in the given path location or
in current directory if path is not supplied.

