"use server";

import { z } from "zod";
import { createClient } from "@/lib/supabase/server";
import { requireAuth } from "@/lib/auth-guard";
import { getKeyManagementInfo, hashSecret, verifySecret } from "@/lib/crypto";
import { createAuditLog } from "@/lib/audit";
import { revalidatePath } from "next/cache";

const pinSchema = z
  .string()
  .regex(/^\d{6}$/, "Security PIN harus terdiri dari tepat 6 digit angka.");

/**
 * Mengatur atau memperbarui Security PIN pengguna menggunakan PBKDF2-HMAC-SHA256 + 128-bit Random Salt.
 * Tahan terhadap serangan Rainbow Table & Brute-Force offline.
 */
export async function setSecurityPin(pin: string) {
  const ctx = await requireAuth();
  const parsed = pinSchema.safeParse(pin);
  if (!parsed.success) {
    return { error: parsed.error.issues[0].message };
  }

  const { hash, salt } = hashSecret(parsed.data);
  const supabase = await createClient();

  const { error } = await supabase
    .from("profiles")
    .update({
      security_pin_hash: hash,
      security_pin_salt: salt,
    })
    .eq("id", ctx.userId);

  if (error) {
    return { error: "Gagal menyimpan Security PIN: " + error.message };
  }

  await createAuditLog(
    "UPDATE",
    "security",
    "Mengatur/memperbarui Security PIN (PBKDF2-HMAC-SHA256 + Random Salt)",
    ctx.userId
  );

  revalidatePath("/settings");
  return { success: true };
}

/**
 * Memverifikasi Security PIN terhadap hash + salt di database (timing-safe).
 */
export async function verifyUserSecurityPin(pin: string) {
  const ctx = await requireAuth();
  const parsed = pinSchema.safeParse(pin);
  if (!parsed.success) {
    return { valid: false, error: parsed.error.issues[0].message };
  }

  const supabase = await createClient();
  const { data: profile, error } = await supabase
    .from("profiles")
    .select("security_pin_hash, security_pin_salt")
    .eq("id", ctx.userId)
    .single();

  if (error || !profile?.security_pin_hash || !profile?.security_pin_salt) {
    return {
      valid: false,
      error: "Security PIN belum diatur. Silakan atur di halaman Pengaturan.",
    };
  }

  const valid = verifySecret(
    parsed.data,
    profile.security_pin_hash,
    profile.security_pin_salt
  );

  if (!valid) {
    await createAuditLog(
      "OTHER",
      "security",
      "Percobaan verifikasi Security PIN gagal",
      ctx.userId
    );
    return { valid: false, error: "Security PIN tidak cocok." };
  }

  return { valid: true };
}

/**
 * Mengambil ringkasan status protokol AAA & Key Management untuk halaman Pengaturan.
 * Tidak pernah mengekspos private key maupun hash PIN.
 */
export async function getSecurityStatus() {
  const ctx = await requireAuth();
  const supabase = await createClient();

  const { data: profile } = await supabase
    .from("profiles")
    .select("security_pin_hash")
    .eq("id", ctx.userId)
    .single();

  const keyInfo = getKeyManagementInfo();

  return {
    role: ctx.role,
    hasSecurityPin: Boolean(profile?.security_pin_hash),
    keyManagement: keyInfo,
  };
}
