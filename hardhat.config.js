require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

// Thứ tự ví cố định: [0]=Admin, [1]=Importer, [2]=Issuing Bank, [3]=Exporter, [4]=Advising Bank
const ROLE_KEYS = [
  "PRIVATE_KEY_ADMIN",
  "PRIVATE_KEY_IMPORTER",
  "PRIVATE_KEY_ISSUING_BANK",
  "PRIVATE_KEY_EXPORTER",
  "PRIVATE_KEY_ADVISING_BANK",
];

const normalizeKey = (k) => (k.startsWith("0x") ? k : `0x${k}`);
const sepoliaAccounts = ROLE_KEYS.map((name) => process.env[name])
  .filter((k) => k && k.trim().length > 0)
  .map((k) => normalizeKey(k.trim()));

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      evmVersion: "cancun",
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {},
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "",
      accounts: sepoliaAccounts,
      chainId: 11155111,
      // Base fee Sepolia thường rất thấp; mặc định Hardhat trả tip 1 gwei → tốn ETH faucet vô ích.
      // Đặt SEPOLIA_GAS_PRICE_GWEI (vd 0.05) để dùng giá cố định; để trống = "auto".
      gasPrice: process.env.SEPOLIA_GAS_PRICE_GWEI
        ? Math.round(parseFloat(process.env.SEPOLIA_GAS_PRICE_GWEI) * 1e9)
        : "auto",
    },
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY || "",
  },
  sourcify: {
    enabled: false,
  },
};
