/**
 * Modul Kriptografi Terpusat — SheepStock (PBL Keamanan Informasi KOM1315)
 *
 * Komponen yang diimplementasikan:
 * 1. Manajemen Kunci (Envelope Encryption): RSA-2048-OAEP-SHA256 membungkus DEK AES-256
 * 2. Enkripsi Data at Rest: AES-256-GCM (Authenticated Encryption, IV 96-bit unik per record)
 * 3. Hash + Salting: PBKDF2-HMAC-SHA256 dengan 128-bit random salt (anti Rainbow Table)
 * 4. Tanda Tangan Digital (Non-Repudiation): RSA-2048-PSS dengan SHA-256
 * 5. Fungsi Hash Integritas: SHA-256 untuk Hash-Chained Audit Log
 *
 * PENTING: File ini HANYA boleh diimpor di sisi server (Server Actions / Server Components / Route Handlers).
 */

import crypto from "node:crypto";

const ENC_PREFIX = "enc:v1:";
const AES_ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // 96-bit IV sesuai standar NIST SP 800-38D untuk GCM
const AUTH_TAG_LENGTH = 16; // 128-bit authentication tag
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = "sha256";

// Cache DEK hasil unwrap di memori server saja (tidak pernah ditulis ke disk/DB)
let cachedDek: Buffer | null = null;
let cachedWrappedDekSource: string | null = null;

function decodeBase64Pem(envVarName: string): string {
  const raw = process.env[envVarName];
  if (!raw || raw.trim() === "") {
    throw new Error(
      `Konfigurasi kriptografi belum lengkap: ${envVarName} tidak ditemukan di .env. Jalankan 'node scripts/generate-keys.mjs'.`
    );
  }
  const trimmed = raw.trim();
  if (trimmed.includes("-----BEGIN")) {
    return trimmed.replace(/\\n/g, "\n");
  }
  return Buffer.from(trimmed, "base64").toString("utf8");
}

/**
 * Membuka (unwrap) Data Encryption Key (DEK) AES-256 menggunakan RSA-2048 Private Key.
 * Raw DEK hanya berada di RAM server dan tidak pernah tersimpan plaintext di kode maupun .env.
 */
export function getDataEncryptionKey(): Buffer {
  const wrappedDekB64 = process.env.CRYPTO_WRAPPED_DEK?.trim();
  if (!wrappedDekB64) {
    throw new Error(
      "CRYPTO_WRAPPED_DEK tidak ditemukan di .env. Jalankan 'node scripts/generate-keys.mjs'."
    );
  }

  if (cachedDek && cachedWrappedDekSource === wrappedDekB64) {
    return cachedDek;
  }

  const rsaPrivateKeyPem = decodeBase64Pem("CRYPTO_RSA_PRIVATE_KEY");
  const wrappedBuffer = Buffer.from(wrappedDekB64, "base64");

  const unwrapped = crypto.privateDecrypt(
    {
      key: rsaPrivateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    wrappedBuffer
  );

  if (unwrapped.length !== 32) {
    throw new Error(`Ukuran DEK hasil unwrap tidak valid (${unwrapped.length} bytes, diharapkan 32 bytes).`);
  }

  cachedDek = unwrapped;
  cachedWrappedDekSource = wrappedDekB64;
  return unwrapped;
}

/**
 * Mengembalikan metadata manajemen kunci yang aman untuk ditampilkan di dashboard admin / audit.
 * TIDAK PERNAH mengembalikan kunci privat atau raw DEK.
 */
export function getKeyManagementInfo() {
  const keyId = process.env.CRYPTO_KEY_ID || "unconfigured";
  const rsaPublicPem = process.env.CRYPTO_RSA_PUBLIC_KEY
    ? decodeBase64Pem("CRYPTO_RSA_PUBLIC_KEY")
    : null;
  const fingerprint = rsaPublicPem
    ? crypto.createHash("sha256").update(rsaPublicPem).digest("hex").slice(0, 16)
    : "unconfigured";

  return {
    keyId,
    algorithm: "AES-256-GCM + RSA-2048-OAEP-SHA256",
    signatureAlgorithm: "RSA-2048-PSS-SHA256",
    hashAlgorithm: "PBKDF2-HMAC-SHA256 (100k iter) + SHA-256",
    publicKeyFingerprint: fingerprint,
    isConfigured: Boolean(
      process.env.CRYPTO_RSA_PRIVATE_KEY &&
        process.env.CRYPTO_WRAPPED_DEK &&
        process.env.CRYPTO_SIGNING_PRIVATE_KEY
    ),
  };
}

/**
 * Cek apakah sebuah string sudah berformat ciphertext SheepStock (enc:v1:...).
 */
export function isEncryptedValue(value: string | null | undefined): boolean {
  return typeof value === "string" && value.startsWith(ENC_PREFIX);
}

/**
 * Enkripsi teks sensitif menggunakan AES-256-GCM (Data at Rest).
 * Menghasilkan format: enc:v1:<iv_base64>:<authTag_base64>:<ciphertext_base64>
 */
export function encryptField(plaintext: string | null | undefined, aad = "sheepstock:v1"): string {
  if (plaintext === null || plaintext === undefined) return "";
  if (plaintext === "") return "";
  // Cegah double-encryption jika data sudah terenkripsi
  if (isEncryptedValue(plaintext)) return plaintext;

  const dek = getDataEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, dek, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  if (aad) {
    cipher.setAAD(Buffer.from(aad, "utf8"));
  }

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${ENC_PREFIX}${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted.toString("base64")}`;
}

/**
 * Dekripsi ciphertext AES-256-GCM.
 * Akan melempar Error jika ciphertext/IV/AuthTag telah dimodifikasi (tampering terdeteksi).
 * Jika data belum berprefix 'enc:v1:' (data legacy), dikembalikan apa adanya.
 */
export function decryptField(ciphertext: string | null | undefined, aad = "sheepstock:v1"): string {
  if (ciphertext === null || ciphertext === undefined) return "";
  if (!isEncryptedValue(ciphertext)) return ciphertext;

  const payload = ciphertext.slice(ENC_PREFIX.length);
  const parts = payload.split(":");
  if (parts.length !== 3) {
    throw new Error("Format ciphertext tidak valid (korup atau dimodifikasi).");
  }

  const [ivB64, authTagB64, dataB64] = parts;
  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(authTagB64, "base64");
  const encryptedData = Buffer.from(dataB64, "base64");

  if (iv.length !== IV_LENGTH || authTag.length !== AUTH_TAG_LENGTH) {
    throw new Error("Panjang IV atau Authentication Tag tidak valid.");
  }

  const dek = getDataEncryptionKey();
  const decipher = crypto.createDecipheriv(AES_ALGORITHM, dek, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  if (aad) {
    decipher.setAAD(Buffer.from(aad, "utf8"));
  }
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  return decrypted.toString("utf8");
}

/**
 * Versi aman untuk tampilan UI: jika ciphertext dimodifikasi langsung di database (tampering),
 * UI tidak crash melainkan menampilkan penanda peringatan integritas.
 */
export function decryptFieldSafe(ciphertext: string | null | undefined, aad = "sheepstock:v1"): string {
  if (ciphertext === null || ciphertext === undefined) return "";
  try {
    return decryptField(ciphertext, aad);
  } catch (err) {
    console.error("[Crypto] Deteksi kegagalan dekripsi / tampering:", err);
    return "[INTEGRITAS GAGAL / DATA DIMODIFIKASI]";
  }
}

/**
 * Hash rahasia (misal Security PIN / Passcode) menggunakan PBKDF2-HMAC-SHA256 + Random Salt.
 */
export function hashSecret(plainSecret: string): { hash: string; salt: string } {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto
    .pbkdf2Sync(plainSecret, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST)
    .toString("hex");
  return { hash: derived, salt };
}

/**
 * Verifikasi rahasia terhadap hash + salt menggunakan timingSafeEqual (anti timing attack).
 */
export function verifySecret(plainSecret: string, expectedHash: string, salt: string): boolean {
  if (!plainSecret || !expectedHash || !salt) return false;
  const derived = crypto.pbkdf2Sync(plainSecret, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
  const expectedBuf = Buffer.from(expectedHash, "hex");
  if (derived.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

/**
 * Fungsi hash SHA-256 deterministik (digunakan untuk payload digest & Hash-Chained Audit Log).
 */
export function sha256(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Mengubah objek JSON menjadi string kanonis (urutan key konsisten) sebelum ditandatangani.
 */
export function canonicalizePayload(payload: Record<string, unknown>): string {
  const sortedKeys = Object.keys(payload).sort();
  const normalized: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    const val = payload[key];
    normalized[key] = val === undefined ? null : val;
  }
  return JSON.stringify(normalized);
}

/**
 * Membuat Tanda Tangan Digital (RSA-2048-PSS + SHA-256) untuk menjamin Non-Repudiation & Integritas.
 */
export function signPayload(payload: Record<string, unknown>): {
  signature: string;
  payloadHash: string;
} {
  const canonical = canonicalizePayload(payload);
  const payloadHash = sha256(canonical);
  const privateKeyPem = decodeBase64Pem("CRYPTO_SIGNING_PRIVATE_KEY");

  const signatureBuf = crypto.sign("sha256", Buffer.from(canonical, "utf8"), {
    key: privateKeyPem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });

  return {
    signature: signatureBuf.toString("base64"),
    payloadHash,
  };
}

/**
 * Memverifikasi Tanda Tangan Digital RSA-PSS terhadap payload data saat ini.
 */
export function verifyPayloadSignature(
  payload: Record<string, unknown>,
  signatureBase64: string | null | undefined
): boolean {
  if (!signatureBase64) return false;
  try {
    const canonical = canonicalizePayload(payload);
    const publicKeyPem = decodeBase64Pem("CRYPTO_SIGNING_PUBLIC_KEY");
    return crypto.verify(
      "sha256",
      Buffer.from(canonical, "utf8"),
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      },
      Buffer.from(signatureBase64, "base64")
    );
  } catch {
    return false;
  }
}
