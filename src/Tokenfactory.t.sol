// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/framework/dao/DAOFactory.sol";
import "../src/framework/dao/DAORegistry.sol";
import {createERC1967Proxy} from "../src/utils/Proxy.sol";
import "../src/framework/plugin/setup/PluginSetupProcessor.sol";
import {PluginSetupRef, hashHelpers} from "../src/framework/plugin/setup/PluginSetupProcessorHelpers.sol";
import "../src/framework/plugin/repo/PluginRepoRegistry.sol";
import "../src/framework/plugin/repo/PluginRepoFactory.sol";
import "../src/plugins/governance/admin/AdminSetup.sol";
import "../src/plugins/governance/multisig/MultisigSetup.sol";
import "../src/framework/utils/ens/ENSSubdomainRegistrar.sol";
import "../src/core/dao/IDAO.sol";
import "../src/core/dao/DAO.sol";
import "../src/core/permission/PermissionManager.sol";
import "../src/framework/utils/TokenFactory.sol";
import "@ensdomains/ens-contracts/contracts/registry/ENS.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";


contract ManagingDao {
    function hasPermission(
        address _where,
        address _who,
        bytes32 _permissionId,
        bytes memory _data
    ) external view returns (bool) {
        return true;
    }
}

contract MockResolver {
    function setAddr(bytes32 node, address addr) external {}
}

contract MockENS {
    MockResolver _resolver;

    constructor() {
        _resolver = new MockResolver();
    }

    //     function setRecord(bytes32 node, address owner, address resolver, uint64 ttl) external virtual;
    // function setSubnodeRecord(bytes32 node, bytes32 label, address owner, address resolver, uint64 ttl) external virtual;
    function setSubnodeOwner(
        bytes32 node,
        bytes32 label,
        address owner
    ) external returns (bytes32) {}

    function setResolver(bytes32 node, address resolver) external {}

    function setOwner(bytes32 node, address owner) external {}

    // function setTTL(bytes32 node, uint64 ttl) external virtual;
    // function setApprovalForAll(address operator, bool approved) external virtual;

    function owner(bytes32 node) external view virtual returns (address) {
        return address(0);
    }

    function resolver(bytes32 node) external view virtual returns (address) {
        return address(_resolver);
    }
    // function ttl(bytes32 node) external virtual view returns (uint64);
    // function recordExists(bytes32 node) external virtual view returns (bool);
    // function isApprovedForAll(address owner, address operator) external virtual view returns (bool);
}

contract AuditTest is Test {
    ManagingDao managingDao;

    MockENS mockENS;

    ENSSubdomainRegistrar ensSubdomainRegistrarImpl;
    ENSSubdomainRegistrar ensSubdomainRegistrar;

    DAORegistry daoRegistryImpl;
    DAORegistry daoRegistry;

    PluginRepoRegistry pluginRepoRegistryImpl;
    PluginRepoRegistry pluginRepoRegistry;

    PluginSetupProcessor pluginSetupProcessor;

    DAOFactory daoFactory;

    PluginRepoFactory pluginRepoFactory;

    AdminSetup adminSetup;
    PluginRepo adminRepo;

    MultisigSetup multisigSetup;
    PluginRepo multisigRepo;

    DAO daoImpl;

    function setUp() public {
        managingDao = new ManagingDao();

        mockENS = new MockENS();

        ensSubdomainRegistrarImpl = new ENSSubdomainRegistrar();
        ensSubdomainRegistrar = ENSSubdomainRegistrar(
            createERC1967Proxy(address(ensSubdomainRegistrarImpl), "")
        );
        ensSubdomainRegistrar.initialize(
            IDAO(address(managingDao)),
            ENS(address(mockENS)),
            bytes32(0x0)
        );

        daoRegistryImpl = new DAORegistry();
        daoRegistry = DAORegistry(
            createERC1967Proxy(address(daoRegistryImpl), "")
        );
        daoRegistry.initialize(
            IDAO(address(managingDao)),
            ensSubdomainRegistrar
        );

        pluginRepoRegistryImpl = new PluginRepoRegistry();
        pluginRepoRegistry = PluginRepoRegistry(
            createERC1967Proxy(address(pluginRepoRegistryImpl), "")
        );
        pluginRepoRegistry.initialize(
            IDAO(address(managingDao)),
            ensSubdomainRegistrar
        );

        pluginSetupProcessor = new PluginSetupProcessor(pluginRepoRegistry);

        daoFactory = new DAOFactory(daoRegistry, pluginSetupProcessor);

        pluginRepoFactory = new PluginRepoFactory(pluginRepoRegistry);

        daoImpl = new DAO();

        // Admin plugin
        adminSetup = new AdminSetup();
        adminRepo = pluginRepoFactory.createPluginRepoWithFirstVersion(
            "admin", // _subdomain
            address(adminSetup), //_pluginSetup
            address(this), // _maintainer
            "first version", //_releaseMetadata,
            "" // _buildMetadata
        );

        // Multisig plugin
        multisigSetup = new MultisigSetup();
        multisigRepo = pluginRepoFactory.createPluginRepoWithFirstVersion(
            "multisig", // _subdomain
            address(multisigSetup), //_pluginSetup
            address(this), // _maintainer
            "first version", //_releaseMetadata,
            "" // _buildMetadata
        );
    }

    function test_PluginSetupProcessor_applyUpdate_UnauthorizedUpgrade() public {
        DAO dao = createDao();

        (address multisigPlugin, IPluginSetup.PreparedSetupData memory preparedSetupData) = installMultisig(dao);

        vm.roll(block.number + 1);

        applyMultisigUpdate(dao, multisigPlugin, preparedSetupData.helpers);
    }

    function createDao() internal returns (DAO dao) {
        dao = DAO(payable(createERC1967Proxy(address(daoImpl), bytes(""))));
        dao.initialize(
            "", // metadata
            address(this), // initialOwner
            address(0), // trustedForwarder
            "" // daoURI
        );
        dao.grant(address(dao), address(this), dao.EXECUTE_PERMISSION_ID());
        dao.grant(address(dao), address(dao), dao.ROOT_PERMISSION_ID());
    }

    function installMultisig(DAO dao) internal returns (address multisigPlugin, IPluginSetup.PreparedSetupData memory preparedSetupData) {
        // Prepare installation of Multisig
        address[] memory multisigMembers = new address[](1);
        multisigMembers[0] = address(this);
        Multisig.MultisigSettings memory multisigSettings = Multisig
            .MultisigSettings({onlyListed: true, minApprovals: 1});
        PluginSetupProcessor.PrepareInstallationParams
            memory prepareInstallationParams = PluginSetupProcessor
                .PrepareInstallationParams({
                    pluginSetupRef: PluginSetupRef({
                        versionTag: PluginRepo.Tag(1, 1),
                        pluginSetupRepo: multisigRepo
                    }),
                    data: abi.encode(multisigMembers, multisigSettings)
                });
        (
            multisigPlugin,
            preparedSetupData
        ) = pluginSetupProcessor.prepareInstallation(
                address(dao),
                prepareInstallationParams
            );

        // Create proposal to install
        DAO.Action[] memory installMultisigActions = new DAO.Action[](3);
        installMultisigActions[0].to = address(dao);
        installMultisigActions[0].data = abi.encodeWithSelector(
            PermissionManager.grant.selector,
            address(dao),
            address(pluginSetupProcessor),
            dao.ROOT_PERMISSION_ID()
        );

        PluginSetupProcessor.ApplyInstallationParams
            memory applyInstallationParams = PluginSetupProcessor
                .ApplyInstallationParams({
                    pluginSetupRef: PluginSetupRef({
                        versionTag: PluginRepo.Tag(1, 1),
                        pluginSetupRepo: multisigRepo
                    }),
                    plugin: multisigPlugin,
                    permissions: preparedSetupData.permissions,
                    helpersHash: hashHelpers(preparedSetupData.helpers)
                });
        installMultisigActions[1].to = address(pluginSetupProcessor);
        installMultisigActions[1].data = abi.encodeWithSelector(
            PluginSetupProcessor.applyInstallation.selector,
            address(dao),
            applyInstallationParams
        );

        installMultisigActions[2].to = address(dao);
        installMultisigActions[2].data = abi.encodeWithSelector(
            PermissionManager.revoke.selector,
            address(dao),
            address(pluginSetupProcessor),
            dao.ROOT_PERMISSION_ID()
        );

        // Execute proposal
        dao.execute(bytes32(0x0), installMultisigActions, 0);
    }

    function applyMultisigUpdate(
        DAO dao,
        address multisigPlugin,
        address[] memory helpers
    ) internal {
        // Prepare update
        MultisigSetup multisigSetupV2 = new MultisigSetup();
        multisigRepo.createVersion(1, address(multisigSetupV2), "", "");

        PluginSetupProcessor.PrepareUpdateParams
            memory prepareUpdateParams = PluginSetupProcessor
                .PrepareUpdateParams({
                    currentVersionTag: PluginRepo.Tag(1, 1),
                    newVersionTag: PluginRepo.Tag(1, 2),
                    pluginSetupRepo: multisigRepo,
                    setupPayload: IPluginSetup.SetupPayload({
                        plugin: multisigPlugin,
                        currentHelpers: helpers,
                        data: ""
                    })
                });
        (
            bytes memory updateInitData,
            IPluginSetup.PreparedSetupData memory updatePreparedSetupData
        ) = pluginSetupProcessor.prepareUpdate(
                address(dao),
                prepareUpdateParams
            );

        // Create proposal to update
        DAO.Action[] memory updateMultisigActions = new DAO.Action[](3);
        updateMultisigActions[0].to = address(dao);
        updateMultisigActions[0].data = abi.encodeWithSelector(
            PermissionManager.grant.selector,
            address(dao),
            address(pluginSetupProcessor),
            dao.ROOT_PERMISSION_ID()
        );

        PluginSetupProcessor.ApplyUpdateParams
            memory applyUpdateParams = PluginSetupProcessor.ApplyUpdateParams({
                plugin: multisigPlugin,
                pluginSetupRef: PluginSetupRef({
                    versionTag: PluginRepo.Tag(1, 2),
                    pluginSetupRepo: multisigRepo
                }),
                initData: updateInitData,
                permissions: updatePreparedSetupData.permissions,
                helpersHash: hashHelpers(updatePreparedSetupData.helpers)
            });
        updateMultisigActions[1].to = address(pluginSetupProcessor);
        updateMultisigActions[1].data = abi.encodeWithSelector(
            PluginSetupProcessor.applyUpdate.selector,
            address(dao),
            applyUpdateParams
        );

        updateMultisigActions[2].to = address(dao);
        updateMultisigActions[2].data = abi.encodeWithSelector(
            PermissionManager.revoke.selector,
            address(dao),
            address(pluginSetupProcessor),
            dao.ROOT_PERMISSION_ID()
        );

        // Execute proposal
        vm.expectRevert(
            abi.encodeWithSelector(DAO.ActionFailed.selector, 1)
        );
        dao.execute(bytes32(uint256(1)), updateMultisigActions, 0);
    }

    function test_PermissionManager_applySingleTargetPermissions_IgnoresGrantWithCondition() public {
        DAO dao = createDao();

        address where = makeAddr("where");
        address who = makeAddr("who");
        bytes32 permissionId = bytes32(uint256(0xdeadbeef));

        PermissionLib.SingleTargetPermission[] memory permissions = new PermissionLib.SingleTargetPermission[](1);
        permissions[0].operation = PermissionLib.Operation.GrantWithCondition;
        permissions[0].who = who;
        permissions[0].permissionId = permissionId;

        DAO.Action[] memory applyPermissionsActions = new DAO.Action[](1);
        applyPermissionsActions[0].to = address(dao);
        applyPermissionsActions[0].data = abi.encodeWithSelector(
            PermissionManager.applySingleTargetPermissions.selector,
            where,
            permissions
        );

        // Execution succeeds...
        dao.execute(bytes32(uint256(0)), applyPermissionsActions, 0);

        // Permission isn't granted
        assertFalse(dao.hasPermission(where, who, permissionId, ""));
    }

    function test_DAO_execute_LowLevelCallsToEmptyCodeSucceed() public {
        DAO dao = createDao();

        address to = address(0xdeadc0de);
        assertEq(to.code.length, 0);

        DAO.Action[] memory actions = new DAO.Action[](1);
        actions[0].to = to;
        actions[0].data = abi.encodeWithSelector(
            IERC20.transfer.selector,
            makeAddr("an important recipient"),
            1_000_000 ether
        );

        // Execute call succeeds
        (, uint256 failureMap) = dao.execute(bytes32(uint256(0)), actions, 0);

        // No failures
        assertEq(failureMap, 0);
    }

    function grantRootPermission(DAO dao, address who) internal {
        DAO.Action[] memory actions = new DAO.Action[](3);
        actions[0].to = address(dao);
        actions[0].data = abi.encodeWithSelector(
            PermissionManager.grant.selector,
            address(dao),
            who,
            dao.ROOT_PERMISSION_ID()
        );

        dao.execute(bytes32(uint256(0)), actions, 0);
    }

    function test_TokenFactory_createToken_MerkleMinterNotUpgradeable(address rando, string memory string1, string memory string2) public {
        DAO dao = createDao();
        TokenFactory tokenFactory = new TokenFactory();
        grantRootPermission(dao, address(tokenFactory));

        TokenFactory.TokenConfig memory tokenConfig = TokenFactory.TokenConfig({
            addr: rando,
            name: string1,
            symbol: string2
        });

        address[] memory receivers = new address[](0);
        uint256[] memory amounts = new uint256[](0);
        GovernanceERC20.MintSettings memory mintSettings = GovernanceERC20.MintSettings({
            receivers: receivers,
            amounts: amounts
        });

        (, MerkleMinter merkleMinter) = tokenFactory.createToken(dao, tokenConfig, mintSettings);

        // Assume we have a new V2 implementation...
        MerkleMinter merkleMinterV2Impl = new MerkleMinter();

        // The following will fail when the UUPS checks if the upgrade came from the proxy (since there's no proxy)
       // vm.expectRevert("Function must be called through active proxy");
        PluginUUPSUpgradeable(merkleMinter).upgradeTo(address(merkleMinterV2Impl));
    }
}