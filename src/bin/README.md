# Demo

1. Run the Regtest locally

```aiignore
docker run --name bitcoin-server -d -v /home/bitcoin:/root/bitcoin -p 18443:18443 -it ruimarinho/bitcoin-core -regtest=1 -rpcbind='0.0.0.0' -rpcallowip='0.0.0.0/0'  -fallbackfee='0.01' -txindex=1 -rpcuser=111111 -rpcpassword=111111 -acceptnonstdtxn=1
```


2. Create the account and mine blocks to get funds. 
```aiignore
export BTC="bitcoin-cli -regtest -rpcuser=111111 -rpcpassword=111111"

$BTC -named createwallet \
    wallet_name=alice \
    passphrase="btcstaker" \
    load_on_startup=true \
    descriptors=false

$BTC loadwallet "alice"

$BTC --rpcwallet=alice -generate 100
```

3. Run the demo
```aiignore
cd collidervm_toy/scripts/demo

export BTC="bitcoin-cli -regtest -rpcuser=111111 -rpcpassword=111111"
export BITCOIN_CLI_CMD_DEMO="$BTC --rpcwallet=alice"
$BTC --rpcwallet=alice walletpassphrase "btcstaker" 6000

cargo build && ./run_full_demo.sh
```

Wait for a moment until it pushes the f1 tx, you need to mine at least one block in another console by ```$BTC --rpcwallet=alice -generate 1```, then it begin to push the f2 tx.


If you get `Please enter the wallet passphrase with walletpassphrase first.`, just do:
```aiignore
$BTC --rpcwallet=alice walletpassphrase "btcstaker" 6000
```
