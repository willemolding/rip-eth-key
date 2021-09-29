# Rip Eth Key

A command line tool to scan through a file looking for the corresponding private key for a known public key

## Usage

```shell
cargo run -- path/to/binary "<uncompressed public key hex string with no 0x prefix>"
```

The public key passed in should be a 130 char hex string.

