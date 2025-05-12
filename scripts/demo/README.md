# Demo
1. Install the dependencies

* Docker

2. Run the Regtest locally

```aiignore
docker compose up -d
```

3. Unlock the wallet

```aiignore
docker exec -it bitcoind-regtest bitcoin-cli -regtest --rpcuser=user --rpcpassword=PaSsWoRd walletpassphrase alicePsWd 600
```