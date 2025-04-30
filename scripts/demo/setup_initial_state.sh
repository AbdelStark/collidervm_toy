#!/bin/bash
set -euo pipefail

# Load .env file if it exists, for BITCOIN_CLI_CMD_DEMO
if [[ -f .env ]]; then
  source .env
fi

################################################################################
#                                  CONSTANTS                                     #
################################################################################

# Default command for bitcoin-cli. Override with BITCOIN_CLI_CMD_DEMO env var.
readonly DEFAULT_BITCOIN_CLI="bitcoin-cli -signet"
# Default funding amount in BTC (adjust as needed for Signet fees + demo value)
readonly DEFAULT_FUNDING_AMOUNT_BTC="0.0002"
# Amount required by the demo binary (in satoshis)
readonly REQUIRED_AMOUNT_SAT=10000
# Enable dry run mode (no actual bitcoin-cli calls)
readonly DRY_RUN=0
readonly LIVE_RUN=1

################################################################################
#                                  FUNCTIONS                                     #
################################################################################

print_usage() {
  echo "Usage: $0 -o|--output <output_file> [-a|--amount <btc_amount>] [-d|--dry-run]"
  echo
  echo "Setup the initial funding transaction for the ColliderVM demo."
  echo "Reads SIGNER_ADDRESS from the output file and funds it."
  echo
  echo "Required arguments:"
  echo "  -o, --output        Parameters file to read SIGNER_ADDRESS from and write funding TX info to."
  echo
  echo "Optional arguments:"
  echo "  -a, --amount        Amount of BTC to fund (default: $DEFAULT_FUNDING_AMOUNT_BTC)"
  echo "  -d, --dry-run       Run in dry-run mode (simulate funding without actual bitcoin-cli calls)"
  echo
  echo "Environment variables:"
  echo "  BITCOIN_CLI_CMD_DEMO  Override default bitcoin-cli command (default: '$DEFAULT_BITCOIN_CLI')"
  exit 1
}

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [setup_initial_state] $1"
}

error() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [setup_initial_state] ERROR: $1" >&2
  exit 1
}

save_param() {
  local param_name=$1
  local param_value=$2
  local output_file=$3

  # Save to file
  echo "export ${param_name}=\"${param_value}\"" >> "$output_file"

  # Also display in terminal
  log "Saved to $output_file: $param_name=$param_value"
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to check if jq is installed
check_jq() {
  if ! command_exists jq; then
    error "jq is not installed. Please install jq (e.g., 'sudo apt-get install jq' or 'brew install jq')."
  fi
}

# Function to wait for transaction confirmation (optional, basic implementation)
wait_for_confirmation() {
    local txid=$1
    local confirmations_needed=1
    log "Waiting for $confirmations_needed confirmation(s) for TXID: $txid... (This might take a while on Signet)"
    while true; do
        local confirmations
        # Check if the transaction exists and get confirmations
        confirmations=$($bitcoin_cli gettransaction "$txid" 2>/dev/null | jq -r '.confirmations // 0')

        if [[ "$?" -eq 0 && "$confirmations" -ge "$confirmations_needed" ]]; then
            log "Transaction $txid has $confirmations confirmation(s)."
            break
        fi
        log "TXID $txid not confirmed yet ($confirmations/$confirmations_needed confirmations). Checking again in 15 seconds..."
        sleep 15
    done
}

################################################################################
#                              PARSE ARGUMENTS                                   #
################################################################################

funding_amount_btc=$DEFAULT_FUNDING_AMOUNT_BTC
output_file=""
run_mode=$LIVE_RUN

while [[ $# -gt 0 ]]; do
  case $1 in
    -o|--output)
      output_file=$2
      shift 2
      ;;
    -a|--amount)
      funding_amount_btc=$2
      shift 2
      ;;
    -d|--dry-run)
      run_mode=$DRY_RUN
      shift
      ;;
    *)
      print_usage
      ;;
  esac
done

if [[ -z "$output_file" ]]; then
  error "Output file must be specified with -o or --output."
fi

# Validate amount is a valid number
if ! [[ $funding_amount_btc =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  error "Invalid amount specified: $funding_amount_btc"
fi

# Check dependencies for live mode
if [[ $run_mode -eq $LIVE_RUN ]]; then
  check_jq
fi

################################################################################
#                              INITIALIZATION                                    #
################################################################################

log "Starting initial state setup"
log "Output file: $output_file"
log "Funding amount: $funding_amount_btc BTC"
[[ $run_mode -eq $DRY_RUN ]] && log "Running in DRY RUN mode - no bitcoin-cli commands will be executed"

# Set bitcoin-cli command
bitcoin_cli=${BITCOIN_CLI_CMD_DEMO:-$DEFAULT_BITCOIN_CLI}

# Don't log the bitcoin-cli command (need to sanitize the command to hide potential secrets)
#log "Using bitcoin-cli command: $bitcoin_cli"

# Verify bitcoin-cli works in live mode
if [[ $run_mode -eq $LIVE_RUN ]]; then
  if ! $bitcoin_cli getblockchaininfo > /dev/null 2>&1; then
      error "Failed to execute bitcoin-cli command: $bitcoin_cli. Check configuration and node status."
  fi
fi

# Load existing parameters (SIGNER_ADDRESS is needed)
if [[ ! -f "$output_file" ]]; then
  error "Parameters file not found: $output_file. Please run the main script first."
fi

log "Loading parameters from $output_file"
source "$output_file" || error "Failed to source parameters file: $output_file"

if [[ -z "${SIGNER_ADDRESS:-}" ]]; then
  error "SIGNER_ADDRESS not found in $output_file. Cannot proceed with funding."
fi

# Check if funding amount meets the minimum required by the demo
funding_amount_sat=$(echo "scale=0; $funding_amount_btc * 100000000 / 1" | bc)
if [[ $funding_amount_sat -lt $REQUIRED_AMOUNT_SAT ]]; then
    error "Funding amount $funding_amount_btc BTC ($funding_amount_sat sat) is less than the required minimum $REQUIRED_AMOUNT_SAT sat."
fi

################################################################################
#                           CREATE FUNDING TRANSACTION                           #
################################################################################

log "Funding the Signer Address: $SIGNER_ADDRESS"

if [[ $run_mode -eq $DRY_RUN ]]; then
  # Generate a simulated transaction ID in dry run mode
  funding_txid="dry_run_funding_txid_$(date +%s)"
  log "[DRY RUN] Simulating sendtoaddress: $funding_txid"
else
  # Execute the actual bitcoin-cli command in live mode
  log "Sending $funding_amount_btc BTC to $SIGNER_ADDRESS..."
  funding_txid=$($bitcoin_cli sendtoaddress "$SIGNER_ADDRESS" "$funding_amount_btc")

  if [[ -z "$funding_txid" ]]; then
    error "Failed to send funding transaction using '$bitcoin_cli'. Check wallet balance and node status."
  fi
  $bitcoin_cli -generate 10
fi

log "Funding transaction broadcast successfully. TXID: $funding_txid"
save_param "FUNDING_TXID" "$funding_txid" "$output_file"

if [[ $run_mode -eq $DRY_RUN ]]; then
  # In dry run mode, simulate a funding vout of 0
  funding_vout=0
  log "[DRY RUN] Simulating vout: $funding_vout"
else
  # For live mode, optionally wait for confirmation
  # wait_for_confirmation "$funding_txid"
  # For now, we don't wait for confirmation and just pause for a few seconds
  echo "Waiting for 3 seconds before getting transaction details..."
  sleep 3

  # Find the vout corresponding to the signer address in live mode
  # This assumes the Signer address is unique in the outputs of this tx
  log "Getting transaction details to find the correct vout..."
  tx_details=$($bitcoin_cli gettransaction "$funding_txid" true) # Get verbose transaction details

  funding_vout=$(echo "$tx_details" | jq --arg addr "$SIGNER_ADDRESS" -r '.details[] | select(.address == $addr) | .vout')

  if [[ -z "$funding_vout" || ! "$funding_vout" =~ ^[0-9]+$ ]]; then
    error "Could not automatically determine the vout for address $SIGNER_ADDRESS in TXID $funding_txid. Manual intervention might be needed."
  fi
fi

log "Found vout $funding_vout sending to $SIGNER_ADDRESS in TXID $funding_txid."
save_param "FUNDING_VOUT" "$funding_vout" "$output_file"
save_param "FUNDING_AMOUNT_SAT" "$funding_amount_sat" "$output_file"

log "Initial state setup completed successfully."
log "Funding TXID: $funding_txid"
log "Funding Vout: $funding_vout"
if [[ $run_mode -eq $DRY_RUN ]]; then
  log "Note: This was a dry run, no actual transactions were broadcast."
fi 