const { ethers, upgrades } = require("hardhat");

async function main() {
    const admin = process.env.ADMIN;
    const router = process.env.QUICKSWAP_ROUTER;
    const maxSeals = parseInt(process.env.MAX_SEALS || "10000", 10);

    if (!admin) throw new Error("Missing ADMIN in env");
    if (!router) console.warn("Note: QUICKSWAP_ROUTER not set (ok for Phase-1)");

    // CovenantVault
    const CV = await ethers.getContractFactory("CovenantVaultUpgradeable");
    const covenantVault = await upgrades.deployProxy(CV, [admin, maxSeals], { kind: "uups" });
    await covenantVault.waitForDeployment();
    const covenantVaultAddr = await covenantVault.getAddress();
    console.log("CovenantVaultUpgradeable:", covenantVaultAddr);

    // Oracle (stub)
    const Oracle = await ethers.getContractFactory("OracleStub");
    const oracle = await Oracle.deploy();
    await oracle.waitForDeployment();
    const oracleAddr = await oracle.getAddress();
    console.log("OracleStub:", oracleAddr);

    // PD4 mock token
    const PD4 = await ethers.getContractFactory("Pd4TokenMock");
    const pd4 = await PD4.deploy();
    await pd4.waitForDeployment();
    const pd4Addr = await pd4.getAddress();
    console.log("Pd4TokenMock:", pd4Addr);

    // Sacred Treasury
    const ST = await ethers.getContractFactory("SacredTreasuryUpgradeable");
    const sacredTreasury = await upgrades.deployProxy(
        ST,
        [admin, covenantVaultAddr, router || admin],
        { kind: "uups" }
    );
    await sacredTreasury.waitForDeployment();
    const sacredTreasuryAddr = await sacredTreasury.getAddress();
    console.log("SacredTreasuryUpgradeable:", sacredTreasuryAddr);

    // Pd4 Vault
    const PV = await ethers.getContractFactory("Pd4VaultUpgradeable");
    const pd4Vault = await upgrades.deployProxy(
        PV,
        [sacredTreasuryAddr, pd4Addr, pd4Addr], // pd4Minter = token itself (owner will be vault)
        { kind: "uups" }
    );
    await pd4Vault.waitForDeployment();
    const pd4VaultAddr = await pd4Vault.getAddress();
    console.log("Pd4VaultUpgradeable:", pd4VaultAddr);

    // IMPORTANT: transfer token ownership to the vault so minting works
    const tx = await pd4.transferOwnership(pd4VaultAddr);
    await tx.wait();
    console.log("Pd4TokenMock owner -> Pd4Vault (done)");

    // Pd4d
    const P = await ethers.getContractFactory("Pd4dUpgradeable");
    const pd4d = await upgrades.deployProxy(
        P,
        [admin, covenantVaultAddr, oracleAddr],
        { kind: "uups" }
    );
    await pd4d.waitForDeployment();
    const pd4dAddr = await pd4d.getAddress();
    console.log("Pd4dUpgradeable:", pd4dAddr);

    // Output summary
    console.log("\n== Addresses ==");
    console.log(JSON.stringify({
        CovenantVaultUpgradeable: covenantVaultAddr,
        OracleStub: oracleAddr,
        Pd4TokenMock: pd4Addr,
        SacredTreasuryUpgradeable: sacredTreasuryAddr,
        Pd4VaultUpgradeable: pd4VaultAddr,
        Pd4dUpgradeable: pd4dAddr
    }, null, 2));

    console.log("\n== Post-Deploy Checklist ==");
    console.log("- Set per-tx caps:");
    console.log(`  Pd4Vault.setMaxTransferPerTx(<cap>) @ ${pd4VaultAddr}`);
    console.log(`  SacredTreasury.setMaxProvisionPerTx(<cap>) @ ${sacredTreasuryAddr}`);
    console.log("- Allowlist PD4 in treasury:");
    console.log(`  SacredTreasury.setAllowedToken(${pd4Addr}, true)`);
    if (router) {
        console.log("- Router set at deploy; you can change via setRouter(newAddress).");
    } else {
        console.log("- (Optional) Set router later via SacredTreasury.setRouter(<router>)");
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});