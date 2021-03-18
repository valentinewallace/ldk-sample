# ldk-sample
Sample node implementation using LDK.

## Installation
```
git clone git@github.com:valentinewallace/ldk-tutorial-node.git
```

## Usage
```
cd ldk-tutorial-node
cargo run <bitcoind-rpc-username>:<bitcoind-rpc-password>@<bitcoind-rpc-host>:<bitcoind-rpc-port> <ldk_storage_directory_path> [<ldk-incoming-peer-listening-port>] [bitcoin-network]
```
where bitcoin-network defaults to `testnet`, with possible options being `testnet` or `regtest`.

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
