/**
@module vk-controller.js
@author iAmMichaelConnor
@desc this acts as a layer of logic between the restapi.js, which lands the
rest api calls, and the heavy-lifitng token-zkp.js and zokrates.js.  It exists so that the amount of logic in restapi.js is absolutely minimised.
*/
const fs = require('fs');
const { hexToDec } = require('zkp-utils');
const config = require('./config');
const utils = require('./utils');
const Web3 = require('./provider');
const logger = require('./logger');

/**
Loads a verification key to the Verifier Registry
 * @param {String} vkDescription - Description of action that the vk represents, i.e., "mint", "simpleBatchTransfer", "bunr"
 * @param {String} vkJsonFile - Path to vk file in JSON form
 * @param {Object} blockchainOptions
 * @param {Object} blockchainOptions.shieldJson - Compiled JSON of relevant Shield (i.e., NFTokenShield or FTokenShield)
 * @param {String} blockchainOptions.shieldAddress - address of relevant Shield contract (i.e., NFTokenShield or FTokenShield)
 * @param {String} blockchainOptions.account - Account that will send the transactions
*/
async function loadVk(vkDescription, vkJsonFile, blockchainOptions) {
  const { shieldJson, shieldAddress, account } = blockchainOptions;

  // Shield contract expects a uint instead of the string we get.
  let vkUint;
  switch (vkDescription) {
    case 'mint':
      vkUint = 0;
      break;
    case 'transfer':
      vkUint = 1;
      break;
    case 'burn':
      vkUint = 2;
      break;
    case 'simpleBatchTransfer':
      vkUint = 3;
      break;
    case 'consolidationTransfer':
      vkUint = 4;
      break;
    default:
      // intentionally set an invalid enumUint that will fail (because currently only enums 0,1,2,3 exist in the shield contracts) in order to save users gas.
      vkUint = 99;
      break;
  }

  logger.verbose(`Loading VK for ${vkJsonFile}`);

  const web3 = Web3.connection();
  const vkRegistryInstance = new web3.eth.Contract(shieldJson.abi, shieldAddress);

  let vk = JSON.parse(fs.readFileSync(vkJsonFile, 'utf8'));
  vk = Object.values(vk);
  vk = utils.flattenDeep(vk);
  vk = vk.map(el => hexToDec(el));

  // upload the vk to the smart contract
  logger.debug('Registering verification key');
  await vkRegistryInstance.methods.registerVerificationKey(vk, vkUint).send({
    from: account,
    gas: 6500000,
    gasPrice: config.GASPRICE,
  });
}

module.exports = {
  loadVk,
};
