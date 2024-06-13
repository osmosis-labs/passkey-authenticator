#!/bin/bash
set -e

# Description:
# This script stores a contract code, instantiates a contract, and retrieves the contract address.

# Color variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NODE="--node http://164.92.247.225:26657"
CHAIN="--chain-id smartaccount"
KEYRING="--keyring-backend test"
FEES="--fees 62500uosmo"
GAS="--gas 25000000"
OPTS="$KEYRING $CHAIN $NODE $FEES $GAS $BROADCAST"
SENDER="--from val"
ARTIFACTS="./artifacts/passkey_authenticator.wasm"
LABEL="passkey"

# Function to handle error checking
check_error() {
  local error_code=$1
  local error_message=$2
  if [ "$error_code" != "0" ]; then
    echo "${RED}Error: $error_message${NC}"
    exit 1
  fi
}

echo "${YELLOW}Storing code...${NC}"
echo "${CYAN}osmosisd tx wasm store $ARTIFACTS $SENDER $OPTS -o json${NC}"
RESP=$(osmosisd tx wasm store $ARTIFACTS $SENDER $OPTS -y -o json)
check_error "$(echo "$RESP" | jq -r '.code')" "Error in transaction: $(echo "$RESP" | jq -r '.raw_log')"

TX_HASH=$(echo "$RESP" | jq -r '.txhash')
echo "${GREEN}Stored code in transaction:${NC} $TX_HASH"

echo "${YELLOW}Waiting for transaction to be processed...${NC}"
sleep 3
echo "${GREEN}Transaction processed!${NC}"

echo "${YELLOW}Querying transaction...${NC}"
CMD="osmosisd query tx $NODE $TX_HASH -o json"
echo "${CYAN}$CMD${NC}"
RESP=$($CMD)
SANITIZED_RESP=$(echo "$RESP" | sed 's/^[^,{]*//')
CODE_ID=$(echo "$SANITIZED_RESP" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
echo "${GREEN}* Code id:${NC} $CODE_ID"

INIT="{}"
echo "${YELLOW}Instantiating contract...${NC}"
CMD="osmosisd tx wasm instantiate --label $LABEL --no-admin "$CODE_ID" "$INIT" $SENDER $OPTS -y"
echo "${CYAN}$CMD${NC}"
RESP=$($CMD)

echo "${YELLOW}Waiting for contract instantiation...${NC}"
sleep 3
echo "${GREEN}Contract instantiated!${NC}"

CMD="osmosisd query wasm list-contract-by-code "$CODE_ID" -o json"
echo "${CYAN}$CMD${NC}"
RESP=$($CMD)
CONTRACT=$(echo "$RESP" | jq -r '.contracts[-1]')
echo "${GREEN}## Contract address:${NC} $CONTRACT"

echo "${PURPLE}------------------------------------------${NC}"
echo "${GREEN}Summary:${NC}"
echo "${YELLOW}Transaction Hash:${NC} $TX_HASH"
echo "${YELLOW}Code ID:${NC} $CODE_ID"
echo "${YELLOW}Contract Address:${NC} $CONTRACT"
echo "${PURPLE}------------------------------------------${NC}"