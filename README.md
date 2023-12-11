# ZKretSanta - A truly secret, Secret Santa protocol
ZKretSanta is a protocol that allows for *trustless* generation of Secret Santa assingments. It has been realized as a custom mini-blockchain using the Avalanche platform.

## Motivation
[Secret Santa](https://en.wikipedia.org/wiki/Secret_Santa) is a fun Christmas tradition. The traditional game of drawing names from a hat or a bowl works well for secretly deciding who gives gifts to whom. But it doesn't work for remote/online communities who can't meet in person to draw the names. Such communities inevitably end up relying on a trusted party - someone who makes the "master list" or an online centralized (Web2) Secret Santa generator - for making the assignments. This project aims to remove the need for a trusted party by relying on zero-knowledge proofs and blockchain instead.

## How it works
The protocol essentially simulates the traditional game of drawing names from a hat over a blockchain. It works in three phases:
 * **ENTER phase.** This is analogous to placing name chits in a hat in the traditional game. Participants generate a key-pair and publish the public key to the blockchain by sending an ENTER transaction. These public keys are not (yet) linked to the actual identities of the participants.
 * **CHOICE phase.** This is analogous to drawing names from the hat in the traditional game. A participant who has completed the ENTER phase chooses a public key from the list of published public keys. They send a CHOICE transaction to the blockchain to declare their choice. They do so without revealing their own public key by attaching a zero-knowledge proof that they had already published their public key and completed the ENTER phase. They also attach a Diffie Hellman public key to the transaction.
 * **REVEAL phase.** Once a participant's public key has been chosen in a CHOICE transaction, they must reveal their identity to the participant who made that CHOICE transaction (the chooser). They generate the shared secret that will only be shared by them and the chooser by making use of the chooser's Diffie Hellman public key. They use this shared secret to encrypt their identity and send it via the REVEAL transaction. They attach a proof to the transaction that the public key actually belonged to them by using their secret key. They also attach their Diffie Hellman public key to the transaction which the chooser can use to arrive at the same shared secret. The chooser can then decrypt the identity of the person they chose using this shared secret.

## How to run
Make sure you have [avalanchego](https://github.com/ava-labs/avalanchego) and [avalanche-network-runner](https://github.com/ava-labs/avalanche-network-runner) installed. Also ensure that you have the `AVALANCHEGO_EXEC_PATH` and `AVALANCHEGO_PLUGIN_PATH` environment variables set. Then execute the following commands from the project root directory to get the local blockchain network up and running with the custom VM installed:
```bash
cargo build --release
scripts/install.sh
scripts/anr.sh

# In a separate shell 
scripts/vm.sh
```
Note the `chain_id` from the logs. Now you can start interacting with the blockchain and take part in the ZkretSanta protocol by sending transactions as follows:
```bash
# Temporarily add the build directory to PATH
export PATH=$PATH:./target/release

# Generate a keypair file. It will also store the state of the protocol for this keypair.
# This will place the keypair in the current directory with the file name "key.zkret"
# To specify a custom path, use the -k option
zkretctl keygen <chain_id>

# Enter the protocol by publishing the public key to the blockchain
# This will read the keypair from the file "key.zkret" in the current directory
# To specify a custom keypair file path, use the -k option. This applies for all the following commands.
zkretctl enter

# List all the public keys that have been published to the blockchain and are available for choosing
zkretctl choice list

# Choose a public key from the list
zkretctl choice make <choice_public_key>

# Check if you got a santa (i.e. the one who chose your public key)
zkretctl checkymysanta

# Reveal your information to your santa
zkretctl reveal "<info_plaintext>"

# Check if your santee (i.e. the person whose public key you chose) has revealed their information to you
zkretctl checkmysantee
```

