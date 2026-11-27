/**
 * Kiểm tra số dư ETH của 5 ví và (tùy chọn) chia ETH từ ví Admin sang 4 ví còn lại.
 * Nhờ vậy chỉ cần xin faucet cho MỘT ví Admin.
 *
 *  npx hardhat run scripts/check-balances.js --network sepolia
 *  FUND=1 npx hardhat run scripts/check-balances.js --network sepolia   (chia ETH)
 *
 * Biến tùy chọn: FUND_AMOUNT (mặc định 0.02 ETH cho mỗi ví còn thiếu).
 */
const { ethers, network } = require("hardhat");
const { getRoleSigners, explorerTx } = require("./common");

async function main() {
  const signers = await getRoleSigners(ethers);
  const target = ethers.parseEther(process.env.FUND_AMOUNT || "0.02");

  console.log(`\nMạng: ${network.name}`);
  for (const [name, s] of Object.entries(signers)) {
    const bal = await ethers.provider.getBalance(s.address);
    console.log(`  ${name.padEnd(13)} ${s.address}  ${ethers.formatEther(bal)} ETH`);
  }

  if (process.env.FUND !== "1") return;

  console.log(`\nChia ETH từ Admin (mỗi ví tối thiểu ${ethers.formatEther(target)} ETH)`);
  for (const [name, s] of Object.entries(signers)) {
    if (name === "admin") continue;
    const bal = await ethers.provider.getBalance(s.address);
    if (bal >= target) {
      console.log(`  ${name}: đủ, bỏ qua`);
      continue;
    }
    const tx = await signers.admin.sendTransaction({ to: s.address, value: target - bal });
    await tx.wait();
    console.log(`  ✔ ${name} +${ethers.formatEther(target - bal)} ETH  ${explorerTx(tx.hash)}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
