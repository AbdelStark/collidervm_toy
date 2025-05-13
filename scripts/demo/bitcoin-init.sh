#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPCUSER=user
RPCPASSWORD=PaSsWoRd
WALLETNAME=alice
WALLETPASSPHRASE=alicePsWd

bitcoind -daemon \
   -server=1  \
   -datadir=/bitcoin \
   -regtest=1 \
   -txindex=1 \
   -fallbackfee='0.01' \
   -rpcallowip=0.0.0.0/0 \
   -rpcbind=0.0.0.0 \
   -rpcuser=$RPCUSER \
   -rpcpassword=$RPCPASSWORD

BTC="bitcoin-cli -regtest -rpcuser=$RPCUSER -rpcpassword=$RPCPASSWORD"

# Wait until RPC is ready
sleep 5
while ! $BTC getblockchaininfo > /dev/null 2>&1; do
  echo "Waiting for bitcoind..."
  sleep 2
done

$BTC -named createwallet \
    wallet_name=$WALLETNAME \
    passphrase=$WALLETPASSPHRASE \
    load_on_startup=true \
    descriptors=false

$BTC loadwallet $WALLETNAME

$BTC --rpcwallet=$WALLETNAME walletpassphrase $WALLETPASSPHRASE 60

# Fund alice
$BTC --rpcwallet=$WALLETNAME -generate 101

# Install watch
apt-get update
apt-get install -y procps
# A terminal-based program (like watch, top, less, etc.) runs in an environment, TERM environment variable should be set
export TERM=xterm
watch -n 2 "$BTC -generate 1"