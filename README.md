# Mechain-Zk-Wallet

Mechain-Zk-Wallet is simply a zk based prover light wallet.

Mechain-Wallet integrates a set of smart contracts and microservices, and the ZoKrates zk-snark toolkit, to enable standard ERC-20 and ERC-721 tokens to be transacted on the Ethereum blockchain with complete privacy. It is an experimental solution and still being actively developed. We decided to share our research work in the belief that this will speed adoption of public blockchains. This is not intended to be a production-ready application and we do not recommend that you use it as such. If it accelerates your own work, then we are pleased to have helped. We hope that people will feel motivated to contribute their own ideas and improvements.



## Trusted Setup

The `setup/gm17` directory contains the ZoKrates domain-specific language (`.zok`) files that you
need in order to run the Nightlite functions. The `generateZokratesFiles()` function will read these
files and complete the trusted setup for you, skipping the `common` folder, containing shared
functions.

There are actually three sets of `.zok` files, which are selected by using a combination of the
`HASH-TYPE` and `COMPLIANCE` environment variables. Allowed values are 'sha'|'mimc' and 'true'
respectively. Setting other than 'true' for the COMPLIANCE variable will select the conventional
version (either sha or mimc enabled). Use of `HASH_TYPE='mimc'` with `COMPLIANCE='true'` is not
currently supported. The three sets are:

- A set for use with a sha-hashed Merkle tree (the original Nightfall approach `HASH_TYPE='sha'`);
- A set that uses the MiMC hash instead (`HASH_TYPE='mimc'`) giving much faster proof computation
  (about 12x) but higher gas cost for on-chain computation (about 3x); and
- A set that is designed to support regulatory compliance by providing blacklisting and encryption
  of transaction data (`HASH_TYPE='sha'`and `COMPLIANCE='true'`). See
  [el-gamal encryption](./el-gamal.md) and [blacklisting](./blacklist.md).

Note that it is trivial to implement whitelisting too by inverting the blacklisting logic in
Nightfall's FTokenShield.sol contract.

The compliance version uses sha hashing and does not support batched payments or non-fungible tokens
currently. The sha hashing version does not support consolidation proofs and is unlikely ever to do
so because of the very large number of constraints that would be required to generate the proof (a
consolidation proof allows twenty small value commitments to be combined into a single large value
one. This is useful when making batch payments to prevent ever smaller commitment values being
generated by successive transactions).

Calling `generateZokratesFiles()` will generate the files you need for the rest of the Nightfall
protocol to work. If you are running Nightfall, the `./nightfall-generate-trusted-setup` command
calls this function for you.

Otherwise, `generateZokratesFiles()` requires a directory argument telling it where to output the
files. It can take a second optional argument telling it which file to set up. For example:

```sh
generateZokratesFiles('zkp/gm17', 'ft-transfer')
```

will set up only `ft-transfer.zok` and output the files in your `zkp/gm17` directory. If `HASH_TYPE`
is set to `mimc`, the function will automatically set up `mimc/ft-transfer.zok` or
`rc/ft-transfer.zok` in the case of `COMPLIANCE='true'`.

By default, Nightlite will use SHA-256 for merkle tree calculations.

The Trusted Setup step will take approximately one hour. The Trusted Setup step will need to be
re-run for a given .zok file whenever it is changed or whenever you change `HASH_TYPE`.

## ZKP Public/Private Keys

In order to make private transactions, you will need a ZKP public/private key pair. This is separate
from the typical Ethereum public/private key pair.

The ZKP public/private keys are both 32 bytes long. As a string, this a 66 character value (0x + 64
characters).

You can generate a private key by generating any random 32 byte string (you can use our
`utils.randomHex(32)` function).

You can generate your matching public key by hashing it (you can use our `utils.hash()` function).

Just as with typical Ethereum key pairs, losing your private key can mean the loss of any
commitments you hold.

## Deploy Necessary Contracts

The following contracts are necessary for Nightfall:

- Verifier_Registry
- BN256G2
- GM17_v0
- FToken
- FTokenShield
- NFTokenMetadata
- NFTokenShield

The deployment currently occurs in `zkp/migrations/2_Shield_migration.js`. We may move away from
truffle deployments and use web3 or another similar library in the future.

FToken and NFTokenMetadata are placeholder ERC721/ERC20 contracts. In order to replace them, you
need to swap the FToken/NFTokenMetadata contracts in this migration script.

## Deploy VKs to the blockchain

The Verification Keys that we generated earlier in the `Trusted Setup` step need to be deployed to
the blockchain. We deploy them directly to the Shield Contracts. The function `loadVk()` loads the
`vk.json` files we made in the Trusted Setup stage to the Shield contract(s).

`loadVk()` must be called on each `vk.json`. Those VKs must then be uploaded to the FTokenShield and
NFTokenShield contracts via their `registerVerificationKey()` functions. The Shield contract keeps
track of which verification key relates to which function (e.g. it stores which verification key
relates to a 'transfer').

A sample implementation can be found in Nightfall's `zkp/src/vk-controller.js`, in the function
`initializeVks()`.

## Run Nightfall Functions

There are currently six Nightfall functions, `Mint`, `Transfer`, and `Burn` for both ERC20 and
ERC721 contracts. After the above steps are completed, you can call those functions as many times as
you'd like. The above steps do not need to be repeated (assuming your environment is now setup).

Note that there are certain things that need to be stored while running these functions.

When a commitment is generated (whether its through minting a commitment, or `ft-transfer`'s
"change" mechanic), it has a `salt`, a `commitment`, and a `commitmentIndex`. All of these things
are required for later function calls. Refer to the documentation on each individual function for
more information.

A consolidation transfer (`ft-consolidation-transfer`), which takes 20 commitments and sends them in
one proof, is only possible with MiMC hashing due to its efficiency in ZKP circuits. If you would
like to use it, or MiMC hashing in general, be sure to
[re-run](https://github.com/EYBlockchain/nightfall/tree/master/zkp) the trusted setup on the files
in `gm17/mimc`. This can be done by changing the `HASH_TYPE` variable to `'mimc'` and proceeding as
normal.

Note about **MiMC hashing**:

Along with completing the trusted setup with `HASH_TYPE = mimc`, be sure to use the same environment
variable in merkle tree, otherwise there will be a mismatch. Nightlite's core `config.js` and
merkle tree specific `merkleTree/config.js` ensure that the parameters are set correctly for MiMC
hashing, but if you have another global config file, those parameters could be overwritten and cause
issues.

In particular, MiMC hashing requires merkle tree nodes to be 32 bytes long, but SHA uses 27 bytes.
By default Nightlite use NODE_HASHLENGTH of value 27. There exist a override function, which
can be used:

```sh
overrideDefaultConfig({
  NODE_HASHLENGTH: 32
});
```

## To Do

### Passing Providers

Currently, most functions that interact with smart contracts just "know" what the proper provider
is, but this isn't good. We need to figure out how to get these functions their providers.

Here are some possibilities:

1. **Pass the provider to each function**: The most straightforward, but also a lot of clutter
2. Set a "provider" singleton: Requires some additional setup from the user (probably just calling
   `setProvider()` on startup).

### Acknowledgements

Team Nightfall thanks those who have indirectly contributed to it, with the ideas and tools that
they have shared with the community:

- [ZoKrates](https://hub.docker.com/r/michaelconnor/zok)
- [Libsnark](https://github.com/scipr-lab/libsnark)
- [Zcash](https://github.com/zcash/zcash)
- [GM17](https://eprint.iacr.org/2017/540.pdf)
- [0xcert](https://github.com/0xcert/ethereum-erc721/)
- [OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/token/ERC20/ERC20.sol)

Thanks to John Sterlacci for the name `Nightlite`.
