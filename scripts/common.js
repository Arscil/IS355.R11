const fs = require("fs");
const path = require("path");
const { network } = require("hardhat");

const DEPLOY_DIR = path.join(__dirname, "..", "deployments");
const ROLE_NAMES = ["admin", "importer", "issuingBank", "exporter", "advisingBank"];

function deploymentFile(name = network.name) {
  return path.join(DEPLOY_DIR, `${name}.json`);
}

function loadDeployment() {
  const file = deploymentFile();
  if (!fs.existsSync(file)) {
    throw new Error(`Chưa có ${file}. Hãy chạy script deploy cho mạng "${network.name}" trước.`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function saveJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

async function getRoleSigners(ethers) {
  const signers = await ethers.getSigners();
  if (signers.length < ROLE_NAMES.length) {
    throw new Error(
      `Cần ${ROLE_NAMES.length} ví (Admin, Importer, Issuing Bank, Exporter, Advising Bank) nhưng chỉ có ${signers.length}. ` +
        "Kiểm tra các biến PRIVATE_KEY_* trong file .env."
    );
  }
  const out = {};
  ROLE_NAMES.forEach((name, i) => (out[name] = signers[i]));
  return out;
}

function isLive() {
  return !["hardhat", "localhost"].includes(network.name);
}

function explorerTx(hash) {
  return network.name === "sepolia" ? `https://sepolia.etherscan.io/tx/${hash}` : hash;
}

function explorerAddress(addr) {
  return network.name === "sepolia" ? `https://sepolia.etherscan.io/address/${addr}` : addr;
}

module.exports = {
  DEPLOY_DIR,
  ROLE_NAMES,
  deploymentFile,
  loadDeployment,
  saveJson,
  getRoleSigners,
  isLive,
  explorerTx,
  explorerAddress,
};
