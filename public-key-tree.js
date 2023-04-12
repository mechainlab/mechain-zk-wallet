const { PUBLIC_KEY_TREE_HEIGHT, ZOKRATES_PRIME } = require('./config');

const FIRST_LEAF_INDEX = 2 ** PUBLIC_KEY_TREE_HEIGHT - 1;
/**
This function queries the Merkle tree held in PublicKeyTree.sol and returns
the sibling path from the provided leaf (key) up to the root. The root is also
returned as element 0 of the sibling path.
@param {object} contractInstance - and instance of the contract that inherits PublicKeyTree.sol
@param {string} key - the public key leaf that the path is to be computed for
*/
async function getPublicKeyTreeData(contractInstance, _key) {
  const key = `0x${(BigInt(_key) % ZOKRATES_PRIME).toString(16).padStart(64, '0')}`;
  console.log('KEY LENGTH WAS', key.length - 2, key);
  const commitmentIndex = await contractInstance.methods.L(key).call();
  const siblingPath = []; // sibling path
  let s = 0; // index of sibling path node in the merkle tree
  let t = 0; // temp index for next highest path node in the merkle tree
  let p = Number(commitmentIndex);

  const leafIndex = commitmentIndex - FIRST_LEAF_INDEX;
  if (leafIndex < 0) {
    throw Error(
      'The public key is not added to the whitelist yet, please create a mint commitment to add the key',
    );
  }
  for (let r = PUBLIC_KEY_TREE_HEIGHT; r > 0; r--) {
    if (p % 2 === 0) {
      s = p - 1;
      t = Math.floor((p - 1) / 2);
    } else {
      s = p + 1;
      t = Math.floor(p / 2);
    }
    siblingPath[r] = contractInstance.methods.M(s).call();
    p = t;
  }
  siblingPath[0] = contractInstance.methods.M(0).call(); // store the root value here

  return {
    leafIndex,
    siblingPath: await Promise.all(siblingPath),
  };
}

module.exports = { getPublicKeyTreeData };
