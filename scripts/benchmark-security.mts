/**
 * Performance Overhead Benchmark — SheepStock (PBL Keamanan Informasi KOM1315)
 *
 * Mengukur overhead komputasi (ms) dan storage (bytes) secara kuantitatif:
 * 1. Plaintext vs AES-256-GCM (Encrypt & Decrypt) untuk N = 10, 50, 100, 500, 1000 record
 * 2. Storage Size Overhead (Plaintext vs Ciphertext AES-256-GCM)
 * 3. RSA-2048-OAEP Unwrap DEK (Cold vs Cached)
 * 4. RSA-2048-PSS Digital Signature (Sign & Verify)
 * 5. PBKDF2-HMAC-SHA256 (100,000 iter) + Random Salt
 * 6. SHA-256 Hash-Chained Audit Log Verification
 *
 * Jalankan: npx tsx scripts/benchmark-security.mts
 */

import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  encryptField,
  decryptField,
  hashSecret,
  verifySecret,
  signPayload,
  verifyPayloadSignature,
  sha256,
  getDataEncryptionKey,
} from "../src/lib/crypto";

const SAMPLE_RECORDS = Array.from({ length: 1000 }, (_, i) => ({
  customer_name: `Pembeli Peternakan #${i + 1} - CV Mitra Agro Nusantara`,
  illness_description: `Infeksi saluran pernapasan ringan dan demam tahap awal (Kasus #${i + 1})`,
  treatment: `Pemberian antibiotik spektrum luas 5ml intramuskular dan vitamin B-Kompleks`,
  phone: `0812${String(10000000 + i).slice(0, 8)}`,
  selling_price: 2500000 + (i % 10) * 150000,
  live_weight: 32.5 + (i % 15) * 0.8,
  livestock_id: `ls-${String(i + 1).padStart(4, "0")}`,
}));

const BATCH_SIZES = [10, 50, 100, 500, 1000];
const RUNS = 5;

function avg(nums: number[]): number {
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

function round(n: number, digits = 3): number {
  return Number(n.toFixed(digits));
}

function main() {
  console.log("=== SHEEPSTOCK SECURITY PERFORMANCE BENCHMARK (PBL KOM1315) ===\n");

  // 1. Cold vs Warm RSA-2048-OAEP Key Unwrap
  const tUnwrapStart = performance.now();
  getDataEncryptionKey();
  const coldUnwrapMs = performance.now() - tUnwrapStart;

  const warmUnwrapTimes: number[] = [];
  for (let i = 0; i < 100; i++) {
    const t0 = performance.now();
    getDataEncryptionKey();
    warmUnwrapTimes.push(performance.now() - t0);
  }
  const cachedUnwrapMs = avg(warmUnwrapTimes);

  // 2. AES-256-GCM Batch Benchmark (4 kolom sensitif per record, seperti operasi CRUD penuh)
  const aesBatchResults: Array<{
    n: number;
    plaintextCopyMs: number;
    encryptTotalMs: number;
    decryptTotalMs: number;
    encryptPerRecMs: number;
    decryptPerRecMs: number;
    plainBytes: number;
    cipherBytes: number;
    sizeOverheadPct: number;
  }> = [];

  for (const n of BATCH_SIZES) {
    const slice = SAMPLE_RECORDS.slice(0, n);
    const plainTimes: number[] = [];
    const encTimes: number[] = [];
    const decTimes: number[] = [];
    let totalPlainBytes = 0;
    let totalCipherBytes = 0;

    for (let r = 0; r < RUNS; r++) {
      // Baseline: serialisasi plaintext tanpa enkripsi
      const tP0 = performance.now();
      const plainOut = slice.map((item) => ({
        customer_name: item.customer_name,
        illness_description: item.illness_description,
        treatment: item.treatment,
        phone: item.phone,
      }));
      plainTimes.push(performance.now() - tP0);

      // AES-256-GCM Encrypt (4 field sensitif)
      const tE0 = performance.now();
      const encryptedOut = slice.map((item) => ({
        customer_name: encryptField(item.customer_name, "harvest_records:customer_name"),
        illness_description: encryptField(item.illness_description, "health_records:illness_description"),
        treatment: encryptField(item.treatment, "health_records:treatment"),
        phone: encryptField(item.phone, "profiles:phone"),
      }));
      encTimes.push(performance.now() - tE0);

      // AES-256-GCM Decrypt (4 field sensitif)
      const tD0 = performance.now();
      const decryptedOut = encryptedOut.map((item) => ({
        customer_name: decryptField(item.customer_name, "harvest_records:customer_name"),
        illness_description: decryptField(item.illness_description, "health_records:illness_description"),
        treatment: decryptField(item.treatment, "health_records:treatment"),
        phone: decryptField(item.phone, "profiles:phone"),
      }));
      decTimes.push(performance.now() - tD0);

      if (r === 0) {
        totalPlainBytes = Buffer.byteLength(JSON.stringify(plainOut), "utf8");
        totalCipherBytes = Buffer.byteLength(JSON.stringify(encryptedOut), "utf8");
        if (decryptedOut[0].customer_name !== slice[0].customer_name) {
          throw new Error("Sanity check gagal pada benchmark AES!");
        }
      }
    }

    const encAvg = avg(encTimes);
    const decAvg = avg(decTimes);
    aesBatchResults.push({
      n,
      plaintextCopyMs: round(avg(plainTimes)),
      encryptTotalMs: round(encAvg),
      decryptTotalMs: round(decAvg),
      encryptPerRecMs: round(encAvg / n, 4),
      decryptPerRecMs: round(decAvg / n, 4),
      plainBytes: totalPlainBytes,
      cipherBytes: totalCipherBytes,
      sizeOverheadPct: round(((totalCipherBytes - totalPlainBytes) / totalPlainBytes) * 100, 2),
    });
  }

  // 3. RSA-2048-PSS Digital Signature Benchmark (N = 10, 50, 100)
  const sigBatchResults: Array<{
    n: number;
    signTotalMs: number;
    verifyTotalMs: number;
    signPerTxMs: number;
    verifyPerTxMs: number;
  }> = [];

  for (const n of [10, 50, 100]) {
    const slice = SAMPLE_RECORDS.slice(0, n);
    const tS0 = performance.now();
    const signed = slice.map((item) => {
      const payload = {
        livestock_id: item.livestock_id,
        customer_name: item.customer_name,
        selling_price: item.selling_price,
        live_weight: item.live_weight,
        harvest_type: "jual_hidup",
      };
      return { payload, ...signPayload(payload) };
    });
    const signTotalMs = performance.now() - tS0;

    const tV0 = performance.now();
    for (const s of signed) {
      const ok = verifyPayloadSignature(s.payload, s.signature);
      if (!ok) throw new Error("Sanity check gagal pada benchmark RSA-PSS!");
    }
    const verifyTotalMs = performance.now() - tV0;

    sigBatchResults.push({
      n,
      signTotalMs: round(signTotalMs),
      verifyTotalMs: round(verifyTotalMs),
      signPerTxMs: round(signTotalMs / n, 3),
      verifyPerTxMs: round(verifyTotalMs / n, 3),
    });
  }

  // 4. PBKDF2-HMAC-SHA256 (100,000 iter) + Random Salt Benchmark (10 runs)
  const pbkdfHashTimes: number[] = [];
  const pbkdfVerifyTimes: number[] = [];
  for (let i = 0; i < 10; i++) {
    const t0 = performance.now();
    const { hash, salt } = hashSecret("482910");
    pbkdfHashTimes.push(performance.now() - t0);

    const t1 = performance.now();
    const ok = verifySecret("482910", hash, salt);
    pbkdfVerifyTimes.push(performance.now() - t1);
    if (!ok) throw new Error("Sanity check PBKDF2 gagal!");
  }

  // 5. SHA-256 Hash-Chained Audit Log Benchmark (100 & 500 entries)
  const chainResults: Array<{ n: number; buildChainMs: number; verifyChainMs: number }> = [];
  for (const n of [100, 500]) {
    let prev = "GENESIS";
    const chain: Array<{ prev: string; data: string; hash: string }> = [];
    const tB0 = performance.now();
    for (let i = 0; i < n; i++) {
      const data = `CREATE|livestocks|ls-${i}|Tambah ternak #${i}|2026-06-01T00:00:00.000Z`;
      const hash = sha256(`${prev}|${data}`);
      chain.push({ prev, data, hash });
      prev = hash;
    }
    const buildChainMs = performance.now() - tB0;

    const tV0 = performance.now();
    let expectedPrev = "GENESIS";
    for (const entry of chain) {
      if (entry.prev !== expectedPrev) throw new Error("Chain broken!");
      if (sha256(`${entry.prev}|${entry.data}`) !== entry.hash) throw new Error("Hash mismatch!");
      expectedPrev = entry.hash;
    }
    const verifyChainMs = performance.now() - tV0;

    chainResults.push({
      n,
      buildChainMs: round(buildChainMs),
      verifyChainMs: round(verifyChainMs),
    });
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      cryptoEngine: `OpenSSL ${process.versions.openssl}`,
      runsPerBatch: RUNS,
    },
    keyManagement: {
      rsa2048OaepColdUnwrapMs: round(coldUnwrapMs, 3),
      cachedMemoryLookupMs: round(cachedUnwrapMs, 5),
    },
    aes256Gcm: aesBatchResults,
    rsa2048PssSignature: sigBatchResults,
    pbkdf2Sha256: {
      iterations: 100000,
      avgHashMs: round(avg(pbkdfHashTimes), 2),
      avgVerifyMs: round(avg(pbkdfVerifyTimes), 2),
    },
    auditHashChainSha256: chainResults,
  };

  const outPath = path.resolve(process.cwd(), "docs", "benchmark_results.json");
  fs.writeFileSync(outPath, JSON.stringify(summary, null, 2), "utf8");

  console.log(JSON.stringify(summary, null, 2));
  console.log(`\nHasil benchmark tersimpan di: ${outPath}`);
}

main();
