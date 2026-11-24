/**
 * Generator Kunci Kriptografi — SheepStock (PBL Keamanan Informasi KOM1315)
 *
 * Membangkitkan:
 * 1. RSA-2048 Key Pair (Key Wrapping / Envelope Encryption - OAEP SHA-256)
 * 2. AES-256 Data Encryption Key (DEK) yang langsung dibungkus (wrapped) dengan RSA Public Key
 *    (Raw DEK TIDAK PERNAH disimpan ke file / database)
 * 3. RSA-2048 Signing Key Pair (Digital Signature - RSA-PSS SHA-256)
 *
 * Cara pakai:
 *   node scripts/generate-keys.mjs          -> otomatis menulis ke .env
 *   node scripts/generate-keys.mjs --force  -> regenerate ulang walau key sudah ada di .env
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const envPath = path.resolve(process.cwd(), ".env");
const force = process.argv.includes("--force");

function toBase64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

function generateKeys() {
  // 1. RSA-2048 Key Pair untuk Envelope Encryption (Key Wrapping)
  const kekPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  // 2. Bangkitkan 256-bit AES DEK di memori, langsung bungkus dengan RSA-OAEP-SHA256
  const rawDek = crypto.randomBytes(32);
  const wrappedDek = crypto.publicEncrypt(
    {
      key: kekPair.publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    rawDek
  );
  // Bersihkan raw DEK dari buffer memori
  rawDek.fill(0);

  // 3. RSA-2048 Key Pair untuk Digital Signature (RSA-PSS SHA-256)
  const signingPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  // 4. Fingerprint & Key ID untuk audit / metadata
  const fingerprint = crypto
    .createHash("sha256")
    .update(kekPair.publicKey)
    .digest("hex")
    .slice(0, 16);
  const keyId = `shp-key-v1-${fingerprint.slice(0, 8)}`;

  return {
    CRYPTO_KEY_ID: keyId,
    CRYPTO_RSA_PUBLIC_KEY: toBase64(kekPair.publicKey),
    CRYPTO_RSA_PRIVATE_KEY: toBase64(kekPair.privateKey),
    CRYPTO_WRAPPED_DEK: wrappedDek.toString("base64"),
    CRYPTO_SIGNING_PUBLIC_KEY: toBase64(signingPair.publicKey),
    CRYPTO_SIGNING_PRIVATE_KEY: toBase64(signingPair.privateKey),
    fingerprint,
  };
}

function main() {
  let envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, "utf8") : "";

  const alreadyConfigured =
    /^CRYPTO_WRAPPED_DEK=.+/m.test(envContent) &&
    /^CRYPTO_RSA_PRIVATE_KEY=.+/m.test(envContent);

  if (alreadyConfigured && !force) {
    console.log("Kunci kriptografi sudah terpasang di .env. Gunakan --force jika ingin rotasi kunci baru.");
    return;
  }

  const keys = generateKeys();

  // Hapus baris lama atau baris komentar placeholder CRYPTO_*
  const lines = envContent.split(/\r?\n/).filter((line) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("# === Cryptography")) return false;
    if (/^#?\s*CRYPTO_(KEY_ID|RSA_PRIVATE_KEY|RSA_PUBLIC_KEY|WRAPPED_DEK|SIGNING_PRIVATE_KEY|SIGNING_PUBLIC_KEY)=/.test(trimmed)) {
      return false;
    }
    return true;
  });

  // Hapus trailing empty lines berlebih
  while (lines.length > 0 && lines[lines.length - 1].trim() === "") {
    lines.pop();
  }

  const block = [
    "",
    "# === Cryptography & Key Management (PBL KI - Auto-generated) ===",
    `CRYPTO_KEY_ID="${keys.CRYPTO_KEY_ID}"`,
    `CRYPTO_RSA_PUBLIC_KEY="${keys.CRYPTO_RSA_PUBLIC_KEY}"`,
    `CRYPTO_RSA_PRIVATE_KEY="${keys.CRYPTO_RSA_PRIVATE_KEY}"`,
    `CRYPTO_WRAPPED_DEK="${keys.CRYPTO_WRAPPED_DEK}"`,
    `CRYPTO_SIGNING_PUBLIC_KEY="${keys.CRYPTO_SIGNING_PUBLIC_KEY}"`,
    `CRYPTO_SIGNING_PRIVATE_KEY="${keys.CRYPTO_SIGNING_PRIVATE_KEY}"`,
    "",
  ];

  fs.writeFileSync(envPath, [...lines, ...block].join("\n"), "utf8");

  console.log("Berhasil membangkitkan kunci kriptografi dan menyimpannya ke .env!");
  console.log(`  Key ID          : ${keys.CRYPTO_KEY_ID}`);
  console.log(`  KEK Fingerprint : ${keys.fingerprint}`);
  console.log("  Envelope Alg    : RSA-2048-OAEP-SHA256 + AES-256-GCM");
  console.log("  Signature Alg   : RSA-2048-PSS-SHA256");
  console.log("  Catatan         : Raw DEK tidak pernah ditulis ke disk. Salin baris CRYPTO_* ke .env VPS juga.");
}

main();
