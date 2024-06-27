# PROCESS

## Step #1 Silver thread - POC
1. Create a GRPC to talk directly to the smart contract from the mobile.
2. Use the webauthn sign to sign the message and using the query get an ok on the transaction being signed.
   1. We want to understand what the signed bytes are --    
   2. Use similar payload to one click trading but GRCP encoded and hit the node.

construct the message correctly:
sign bank send.
mobile signing with r1
async sendExecuteContractMsg(

## Step #2 Scaffolding - MVP for passkeys
1. Write the authenticate function in the authenticator using the secp verify.
2. Integrate unit tests, make sure that it's as production ready
   1. Define the authenticate params, that it is well documented and makes sense.
   2. Generating r1 keys on the Rust side, and calling the sudo-authenticate function.
   3. Spend some time on integration tests.
   4. Spend time on unit test.
   5. Code/pair/review with team memebers.
   6. Ensure Contract API is satisfied -- authenticate/track/confirm_exection

## Step #3 E2E
1. (goland) Add Passkey authenticator to an address from
2. (mobile) execute signed swap messages in mobiles
   1. query sqs node
   2. get route
   3. swap.