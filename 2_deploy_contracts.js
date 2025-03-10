
const AuthSignatureManager = artifacts.require("AuthSignatureManager");


console.log("=== AuthSignatureManager Deployment Details ===");

module.exports = async function (deployer, network, accounts) {
    
    // Deploy AuthSignatureManager and capture the deployment result
    const authSigManagerInstance = await deployer.deploy(AuthSignatureManager);
};