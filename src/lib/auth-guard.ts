/**
 * Authorization & RBAC Guard Terpusat — SheepStock (PBL Keamanan Informasi KOM1315)
 *
 * Menjamin setiap Server Action mematuhi prinsip AAA (Authentication & Authorization):
 * 1. Memastikan pengguna terautentikasi (valid session JWT Supabase)
 * 2. Memvalidasi peran (RBAC: owner / admin / staff)
 * 3. Mengembalikan effectiveUserId (tenant isolation) agar tidak terjadi IDOR lintas peternakan
 */

import { createClient } from "@/lib/supabase/server";

export type UserRole = "owner" | "admin" | "staff" | "inactive";

export type AuthContext = {
  userId: string;
  email: string | null;
  role: UserRole;
  effectiveUserId: string;
  name: string;
};

export async function requireAuth(): Promise<AuthContext> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    throw new Error("Akses ditolak: Silakan login terlebih dahulu.");
  }

  const { data: profile } = await supabase
    .from("profiles")
    .select("role, owner_id, name")
    .eq("id", user.id)
    .single();

  const role = (profile?.role as UserRole) || "staff";
  if (role === "inactive") {
    throw new Error("Akses ditolak: Akun Anda sedang dinonaktifkan oleh Owner.");
  }

  const effectiveUserId =
    role === "staff" && profile?.owner_id ? profile.owner_id : user.id;

  return {
    userId: user.id,
    email: user.email ?? null,
    role,
    effectiveUserId,
    name: profile?.name || user.user_metadata?.full_name || "User",
  };
}

export async function requireRole(allowedRoles: UserRole[]): Promise<AuthContext> {
  const ctx = await requireAuth();
  if (!allowedRoles.includes(ctx.role)) {
    throw new Error(
      `Otorisasi ditolak: Aksi ini hanya diizinkan untuk peran [${allowedRoles.join(", ")}]. Peran Anda saat ini: ${ctx.role}.`
    );
  }
  return ctx;
}
