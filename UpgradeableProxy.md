## Vulnerability Title
`MerkleMinter` created through `TokenFactory` cannot be upgraded.
https://github.com/code-423n4/2023-03-aragon
https://github.com/code-423n4/2023-03-aragon/blob/main/packages/contracts/src/framework/utils/TokenFactory.sol#L119-L125
https://github.com/code-423n4/2023-03-aragon/blob/main/packages/contracts/src/plugins/token/MerkleMinter.sol#L20


## Vulnerability Details or Impact
During the token creation process in the TokenFactory contract, the function creates a MerkleMinter contract to setup and handle token initial token distribution. The MerkleMinter contract is an upgradeable contract, as it inherits from PluginUUPSUpgradeable.
However,the MerkleMinter instance created in createToken is a cloned instance (using OpenZeppelin Clones library). This is incompatible with upgradeable contracts, which require the use of a proxy. This issue will cause the MerkleMinter instance created through TokenFactory to fail to be upgraded. The MerkleMinter contract will contain all the required logic to be upgraded, but the action will fail as there is no proxy to change to a new potential implementation.


## Lines of Code
```solidity
   address merkleMinter = merkleMinterBase.clone();
   MerkleMinter(merkleMinter).initialize(
    _managingDao,
    IERC20MintableUpgradeable(token),
    distributorBase
  );

  contract MerkleMinter is IMerkleMinter, PluginUUPSUpgradeable
```

## Mitigation
The MerkleMinter instance should be created using a proxy over the base implementation (createERC1967Proxy) instead of cloning the implementation.
 