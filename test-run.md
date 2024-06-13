
## Uplading and Instantiating the contract


### Compile the passkey_authenticator

```bash
cargo optimize
```
or
```bash
cargo run-script optimize
```
or
```bash
docker run --rm -v "$(pwd)":/code \     
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/optimizer:0.15.0
```


### Find an edgenet node 
- http://164.92.247.225:26657 this one is the one we use for the front end.

--> `NODE_ADDR` is http://164.92.247.225:26657
```bash
export NODE_ADDR=http://164.92.247.225:26657
```


 ### get testnet keys
 make localnet --help 
 ```bash
 ≈ 
 ```
 
### Upload the binary using the following this store command - and grab the transaction hash
```bash
 cd artifacts
 osmosisd tx wasm store ./artifacts/passkey_authenticator.wasm --from val --keyring-backend test --chain-id smartaccount --node $NODE_ADDR --fees 40000uosmo --gas 10000000
```

--> `tx` is: D5B3E5AC07C623C1D7F63A8B0F702157939AFB734AF34FCD6C13DD31FDD2529C

 ### Query the Tx to get the code-id
 ```bash 
 osmosisd query tx --node $NODE_ADDR D5B3E5AC07C623C1D7F63A8B0F702157939AFB734AF34FCD6C13DD31FDD2529C
```
--> `code-id` is 827
```bash
export CODE_ID=827
```

### Query the code-id to verify the wasm blob 

**(<-- This just verifies that it works, just for safty or if something goes wrong. We don't really need this.)**
```bash
osmosisd query wasm code-info 827 --node $NODE_ADDR
```

 ## Instantiate the contract, with no argyument in the `InstantiateMsg`
```bash
 osmosisd tx wasm instantiate 827 "{}" --label "passkey" --no-admin --gas-prices 0.25uosmo --gas auto --gas-adjustment 1.5 --from val --keyring-backend test --chain-id smartaccount --node $NODE_ADDR
```

## Grab the `txhash` from the (instantiate) payload, and query the tx to get the contract address:
```bash
osmosisd query tx --node $NODE_ADDR 5B979E9A998BCD8430168E03CFE0141AC2C9AC0F443F325B7E866397947D2A09
```

## Grab the contract address (`_contract_address`) from the attributes in the (`query tx`) payload. (by default it returns yaml but you can add `--output json`) 
Example:
```yaml
- attributes:
  - index: true
    key: _contract_address
    value: osmo1a23pnstucdzrzgdd34x4g28xawxg4mausk5ptt5dul3808wk4cpqutdztq
  - index: true
    key: action
    value: instantiate
  - index: true
    key: msg_index
    value: "0"
  type: wasm
```

## we are going to use this contract from here on out:
```bash
export CONTRACT_ADDR = osmo1a23pnstucdzrzgdd34x4g28xawxg4mausk5ptt5dul3808wk4cpqutdztq
```

```bash
export CONTRACT_ADDR = osmo1a23pnstucdzrzgdd34x4g28xawxg4mausk5ptt5dul3808wk4cpqutdztq
```

## Query `VerifySecp256R1Signature` (`VerifySecp256R1Signature` query converts into `verify_secp256_r1_signature` when called with the cli)
```bash
osmosisd query wasm contract-state smart osmo1a23pnstucdzrzgdd34x4g28xawxg4mausk5ptt5dul3808wk4cpqutdztq '{"verify_secp256_r1_signature": { "message": "ZHNmbGtqYWpkc2ZhZHNm", "signature": "2Cj9wMWx3DUUii2IKQ4mDcsaZ6O6Y4F5aa973kFK1lZtlMjTVfxG1aSrFA4IfEECRBPV/4dG5VWwF+BXz/Mx3g==", "public_key": "A2MR6q+pOpLtdxh0tHHe2JrEY2KOcvRogtLxHDHzJvOh" }}' --node http://164.92.247.225:26657
```
// turning intu a curl command:
// Create curl this node: http://164.92.247.225:9090 using grpc with that json {"verify_secp256_r1_signature": { "message": "ZHNmbGtqYWpkc2ZhZHNm", "signature": "2Cj9wMWx3DUUii2IKQ4mDcsaZ6O6Y4F5aa973kFK1lZtlMjTVfxG1aSrFA4IfEECRBPV/4dG5VWwF+BXz/Mx3g==", "public_key": "A2MR6q+pOpLtdxh0tHHe2JrEY2KOcvRogtLxHDHzJvOh" }}


generate the passkye and query the verify_secp256_r1_signature with that a payload.

curl http://164.92.247.225:1317/cosmswasm/wasm/v1/contract/osmo177xfj8lvtywmjxw0ep42cuyuz9fuym7nx3x6ldj5s37yjtn782hq5h8eed/smart/eyJ2ZXJpZnlfc2VjcDI1Nl9yMV9zaWduYXR1cmUiOiB7ICJtZXNzYWdlIjogIlpITm1iR3RxWVdwa2MyWmhaSE5tIiwgInNpZ25hdHVyZSI6ICIyQ2o5d01XeDNEVVVpaTJJS1E0bURjc2FaNk82WTRGNWFhOTcza0ZLMWxadGxNalRWZnhHMWFTckZBNElmRUVDUkJQVi80ZEc1Vld3RitCWHovTXgzZz09IiwgInB1YmxpY19rZXkiOiAiQTJNUjZxK3BPcEx0ZHhoMHRISGUySnJFWTJLT2N2Um9ndEx4SERIekp2T2giIH19

curl http://164.92.247.225:1317/cosmswasm/wasm/v1/code/827
curl http://164.92.247.225:26657/cosmswasm/wasm/v1/code/827

curl -X POST http://164.92.247.225:9090 \
     -H "Content-Type: application/json" \
     -d '{"verify_secp256_r1_signature": { "message": "ZHNmbGtqYWpkc2ZhZHNm", "signature": "2Cj9wMWx3DUUii2IKQ4mDcsaZ6O6Y4F5aa973kFK1lZtlMjTVfxG1aSrFA4IfEECRBPV/4dG5VWwF+BXz/Mx3g==", "public_key": "A2MR6q+pOpLtdxh0tHHe2JrEY2KOcvRogtLxHDHzJvOh" }}'
