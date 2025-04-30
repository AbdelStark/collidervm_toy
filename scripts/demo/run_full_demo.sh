#!/bin/bash

set -euo pipefail

################################################################################
#                                  CONSTANTS                                     #
################################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)" # Assumes scripts/demo relative to workspace root
readonly DEFAULT_PARAMS_FILE="demo_params.env"
readonly DEFAULT_INPUT_X=123  # Default value for the input x
readonly DEMO_OUTPUT_DIR="target/demo" # Matches the output dir in src/bin/demo.rs
readonly JSON_TEMP_DIR="$DEMO_OUTPUT_DIR/json" # Directory for temporary JSON output files

################################################################################
#                                  FUNCTIONS                                     #
################################################################################

print_usage() {
  echo "Usage: $0 [options]"
  echo
  echo "Run the ColliderVM demo end-to-end."
  echo
  echo "Options:"
  echo "  -b, --break           Add breakpoints between steps (press Enter to continue)"
  echo "  -p, --params          Parameters file (default: $DEFAULT_PARAMS_FILE)"
  echo "  -x, --input-x         Input value for x (default: $DEFAULT_INPUT_X)"
  echo "  -d, --dry-run         Perform a dry run for sending transactions"
  echo "  -h, --help            Show this help message"
}

log() {
  local msg=$1
  local timestamp
  timestamp=$(date +'%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] $msg"
}

error() {
  log "ERROR: $1" >&2
  exit 1
}

print_section() {
  local title=$1
  local line="=================================================================="
  echo
  echo "$line"
  echo "                         $title"
  echo "$line"
  echo
}

wait_for_user() {
  if [[ $use_breakpoints == true ]]; then
    read -r -p "Press Enter to continue..."
  fi
}

run_script() {
  local script_path=$1
  shift # Remove script path from args
  
  log "Running script: $script_path $*"

  if ! "$script_path" "$@"; then
    error "Failed to execute: $script_path $*"
  fi

  log "Successfully completed: $script_path"
}

save_param() {
  local param_name=$1
  local param_value=$2
  local output_file=$3

  echo "export ${param_name}=\"${param_value}\"" >> "$output_file"
  log "Saved to $output_file: $param_name=$param_value"
}

################################################################################
#                              PARSE ARGUMENTS                                   #
################################################################################

use_breakpoints=false
params_file="$DEFAULT_PARAMS_FILE"
input_x=$DEFAULT_INPUT_X
dry_run_send=false

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--break)
      use_breakpoints=true
      shift
      ;;
    -p|--params)
      params_file=$2
      shift 2
      ;;
    -x|--input-x)
      input_x=$2
      shift 2
      ;;
    -d|--dry-run)
      dry_run_send=true
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      print_usage
      error "Unknown option: $1"
      ;;
  esac
done

################################################################################
#                              INITIALIZATION                                    #
################################################################################

cd "$WORKSPACE_DIR" || error "Failed to change directory to $WORKSPACE_DIR"

log "Starting ColliderVM Demo Orchestration"
log "Parameters file: $params_file"
log "Using input x value: $input_x"
[[ "$use_breakpoints" == true ]] && log "Breakpoints enabled."
[[ "$dry_run_send" == true ]] && log "Send transactions in DRY RUN mode."

# Initialize params file
log "Initializing parameters file: $params_file"
> "$params_file"
save_param "INPUT_X" "$input_x" "$params_file"
save_param "PARAMS_FILE" "$params_file" "$params_file" # Save the params file location itself

# Create directories for JSON output files
mkdir -p "$JSON_TEMP_DIR"

################################################################################
#                   STEP 1: GENERATE SIGNER/OPERATOR KEYS                      #
################################################################################

print_section "STEP 1: GENERATING DEMO KEYS & ADDRESSES"

log "Generating Signer and Operator keys and addresses using demo binary..."
# We run the demo binary once without funding to get the addresses printed
# In a real scenario, you might have a dedicated key generation tool or read from config
# For this demo, we capture the output of the first run

# Run the command and capture its output
# Assuming the binary is built and in the target/debug or target/release path
# Adjust CARGO_TARGET_DIR if needed
demo_bin_path="${CARGO_TARGET_DIR:-target/debug}/demo"
if [ ! -x "$demo_bin_path" ]; then
    demo_bin_path="${CARGO_TARGET_DIR:-target/release}/demo"
fi

if [ ! -x "$demo_bin_path" ]; then
    log "Attempting to build the demo binary first..."
    if cargo build --bin demo; then
        log "Build successful."
        demo_bin_path="${CARGO_TARGET_DIR:-target/debug}/demo" # Re-check debug path first
         if [ ! -x "$demo_bin_path" ]; then
             demo_bin_path="${CARGO_TARGET_DIR:-target/release}/demo"
         fi
         if [ ! -x "$demo_bin_path" ]; then
             error "Could not find demo binary even after building."
         fi
    else
        error "Failed to build demo binary. Please build it first."
    fi
fi

# Function to check if jq is installed
check_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    error "jq is not installed. Please install jq (e.g., 'sudo apt-get install jq' or 'brew install jq')."
  fi
}

# Check dependencies
check_jq

# JSON file for key generation output
keys_json_file="$JSON_TEMP_DIR/keys.json"

log "Running '$demo_bin_path' to generate keys/addresses (no funding yet)..."
"$demo_bin_path" --x "$input_x" --json --json-output-file "$keys_json_file"

# Check if JSON file was created
if [ ! -f "$keys_json_file" ]; then
    error "Failed to create keys JSON file: $keys_json_file"
fi

# Parse JSON output from file to extract keys and addresses
signer_address=$(jq -r '.keys.signer.address' "$keys_json_file")
operator_address=$(jq -r '.keys.operator.address' "$keys_json_file")
signer_wif=$(jq -r '.keys.signer.wif' "$keys_json_file")
operator_wif=$(jq -r '.keys.operator.wif' "$keys_json_file")

if [[ -z "$signer_address" ]] || [[ -z "$operator_address" ]] || [[ -z "$signer_wif" ]] || [[ -z "$operator_wif" ]]; then
  error "Failed to extract keys from JSON file: $keys_json_file"
fi

# Save addresses and WIFs to params file
save_param "SIGNER_ADDRESS" "$signer_address" "$params_file"
save_param "OPERATOR_ADDRESS" "$operator_address" "$params_file"
save_param "SIGNER_WIF" "$signer_wif" "$params_file"
save_param "OPERATOR_WIF" "$operator_wif" "$params_file"
log "Extracted Signer Address: $signer_address"
log "Extracted Operator Address: $operator_address"

wait_for_user

################################################################################
#                         STEP 2: SETUP INITIAL STATE                           #
################################################################################

print_section "STEP 2: SETTING UP INITIAL FUNDING TRANSACTION"

# Note: The demo binary expects funding to the SIGNER address.
# The setup_initial_state.sh script will handle funding this address.
log "Running setup_initial_state.sh script to fund the signer address..."
if [[ "$dry_run_send" == true ]]; then
    # In dry run mode, simulate funding by creating fake funding info
    log "[DRY RUN] Simulating funding transaction"
    save_param "FUNDING_TXID" "dry_run_funding_txid_$(date +%s)" "$params_file"
    save_param "FUNDING_VOUT" "0" "$params_file"
    save_param "FUNDING_AMOUNT_SAT" "10000" "$params_file"
else
    # In live mode, actually fund the address
    run_script "$SCRIPT_DIR/setup_initial_state.sh" "-o" "$params_file"
fi
wait_for_user

# Source the updated parameters file as setup_initial_state.sh adds variables
log "Reloading parameters from $params_file"
source "$params_file" || error "Failed to source parameters file: $params_file"

# Verify necessary variables are set
if [[ -z "${FUNDING_TXID:-}" ]] || [[ -z "${FUNDING_VOUT:-}" ]]; then
  error "Required variables (FUNDING_TXID, FUNDING_VOUT) not found in $params_file after setup script."
fi

################################################################################
#                   STEP 3: GENERATE F1/F2 TRANSACTIONS                        #
################################################################################

print_section "STEP 3: GENERATING F1 & F2 TRANSACTIONS"

log "Running '$demo_bin_path' with funding info to generate transaction files..."
log "Using input x = $input_x"

# JSON file for transaction generation output
tx_json_file="$JSON_TEMP_DIR/transactions.json"

# Run the demo binary with funding details and JSON output
run_command="$demo_bin_path --x $input_x -f $FUNDING_TXID --funding-vout $FUNDING_VOUT --json --json-output-file $tx_json_file"
log "Executing: $run_command"

eval "$run_command"
if [ $? -ne 0 ]; then
    error "Failed to generate F1/F2 transactions using '$demo_bin_path'."
fi

# Check if JSON file was created
if [ ! -f "$tx_json_file" ]; then
    error "Failed to create transactions JSON file: $tx_json_file"
fi

# Parse JSON output from file to extract transaction IDs
tx_f1_id=$(jq -r '.transactions.f1.txid' "$tx_json_file")
tx_f2_id=$(jq -r '.transactions.f2.txid' "$tx_json_file")

if [[ -z "$tx_f1_id" ]] || [[ -z "$tx_f2_id" ]]; then
    error "Failed to extract transaction IDs from JSON file: $tx_json_file"
fi

save_param "TX_F1_ID" "$tx_f1_id" "$params_file"
save_param "TX_F2_ID" "$tx_f2_id" "$params_file"

# Check if output directory and files exist
if [[ ! -d "$DEMO_OUTPUT_DIR" ]] || [[ ! -f "$DEMO_OUTPUT_DIR/f1.tx" ]] || [[ ! -f "$DEMO_OUTPUT_DIR/f2.tx" ]]; then
    error "Expected transaction files (f1.tx, f2.tx) not found in $DEMO_OUTPUT_DIR after running demo binary."
fi

log "F1 and F2 transaction files generated successfully in $DEMO_OUTPUT_DIR."
log "F1 transaction ID: $tx_f1_id"
log "F2 transaction ID: $tx_f2_id"
wait_for_user

#################################################################################
##                         STEP 4: SEND DEMO TRANSACTIONS                        #
#################################################################################
#
#print_section "STEP 4: SENDING F1 & F2 TRANSACTIONS"
#
## Prepare arguments for send_demo_transactions.sh
#send_args=()
#if [[ "$dry_run_send" == true ]]; then
#    send_args+=("--dry-run")
#fi
#send_args+=("$DEMO_OUTPUT_DIR") # Pass the directory containing the tx files
#
## Run the send_demo_transactions.sh script
#log "Running send_demo_transactions.sh script to broadcast transactions..."
#run_script "$SCRIPT_DIR/send_demo_transactions.sh" "${send_args[@]}"
#
#################################################################################
##                                 SUMMARY                                        #
#################################################################################
#
#print_section "DEMO COMPLETED"
#
#log "ColliderVM Demo orchestration completed."
#log "Parameters saved to: $params_file"
#log "JSON outputs saved to: $JSON_TEMP_DIR/"
#log "Transaction files saved to: $DEMO_OUTPUT_DIR/"
#if [[ "$dry_run_send" == true ]]; then
#    log "Demo was run in DRY RUN mode - no transactions were broadcast."
#else
#    log "Check the output of bitcoin-cli or a block explorer for transaction confirmations."
#fi
#
#exit 0