'use server'

import { revalidatePath } from 'next/cache'
import { redirect } from 'next/navigation'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'
import { createAuditLog } from '@/lib/audit'

const loginSchema = z.object({
    email: z.string().trim().email('Format email tidak valid.').max(120),
    password: z.string().min(1, 'Kata sandi wajib diisi.').max(128),
})

const registerSchema = z.object({
    name: z.string().trim().min(2, 'Nama minimal 2 karakter.').max(100),
    email: z.string().trim().email('Format email tidak valid.').max(120),
    password: z
        .string()
        .min(8, 'Kata sandi minimal 8 karakter.')
        .max(128)
        .regex(/[A-Za-z]/, 'Kata sandi harus mengandung huruf.')
        .regex(/\d/, 'Kata sandi harus mengandung angka.'),
    passwordConfirm: z.string(),
    role: z.enum(['owner', 'staff']).default('owner'),
    referralCode: z.string().trim().max(32).optional().nullable(),
})

const resetPasswordSchema = z.object({
    password: z
        .string()
        .min(8, 'Kata sandi minimal 8 karakter.')
        .max(128)
        .regex(/[A-Za-z]/, 'Kata sandi harus mengandung huruf.')
        .regex(/\d/, 'Kata sandi harus mengandung angka.'),
    passwordConfirm: z.string(),
})

export async function login(prevState: any, formData: FormData) {
    const supabase = await createClient()

    const parsed = loginSchema.safeParse({
        email: formData.get('email'),
        password: formData.get('password'),
    })

    if (!parsed.success) {
        return { error: parsed.error.issues[0].message }
    }

    const { error } = await supabase.auth.signInWithPassword(parsed.data)

    if (error) {
        // Pesan generik untuk mencegah user/email enumeration
        return { error: 'Email atau kata sandi salah.' }
    }

    // Catat aktivitas LOGIN (AAA - Accounting)
    await createAuditLog('LOGIN', 'auth', `Login berhasil untuk akun ${parsed.data.email}`)

    revalidatePath('/', 'layout')
    redirect('/dashboard')
}

export async function logout() {
    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()
    if (user) {
        await createAuditLog('LOGOUT', 'auth', `Logout dari sistem oleh ${user.email || user.id}`, user.id)
    }
    await supabase.auth.signOut()
    redirect('/')
}

export async function register(prevState: any, formData: FormData) {
    const supabase = await createClient()

    const parsed = registerSchema.safeParse({
        name: formData.get('name'),
        email: formData.get('email'),
        password: formData.get('password'),
        passwordConfirm: formData.get('passwordConfirm'),
        role: (formData.get('role') as string) || 'owner',
        referralCode: formData.get('referralCode') as string | null,
    })

    if (!parsed.success) {
        return { error: parsed.error.issues[0].message }
    }

    const { name, email, password, passwordConfirm, role, referralCode } = parsed.data

    if (password !== passwordConfirm) {
        return { error: 'Konfirmasi kata sandi tidak cocok.' }
    }

    let ownerId: string | null = null

    if (role === 'staff') {
        if (!referralCode || referralCode.trim() === '') {
            return { error: 'Kode referral wajib diisi untuk pendaftaran Staff.' }
        }

        // Gunakan RPC SECURITY DEFINER agar tabel profiles tidak perlu dibuka ke publik (anon)
        const { data: rpcOwnerId, error: rpcError } = await supabase.rpc('find_owner_by_referral', {
            p_code: referralCode.trim().toUpperCase(),
        })

        if (rpcError || !rpcOwnerId) {
            return { error: 'Kode referral tidak valid atau pemilik peternakan tidak ditemukan.' }
        }

        ownerId = rpcOwnerId as string
    }

    const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
            data: {
                full_name: name,
                role,
                owner_id: ownerId,
            },
            emailRedirectTo: `${process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000'}/auth/callback`,
        }
    })

    if (error) {
        return { error: 'Pendaftaran tidak dapat diproses. Silakan periksa data Anda dan coba lagi.' }
    }

    // Mencegah email enumeration: tidak membocorkan secara eksplisit apakah email sudah terdaftar
    if (data?.user && data.user.identities && data.user.identities.length === 0) {
        return { success: true, email }
    }

    return { success: true, email }
}

export async function resendVerification(email: string) {
    const parsedEmail = z.string().trim().email().safeParse(email)
    if (!parsedEmail.success) {
        return { error: 'Format email tidak valid.' }
    }

    const supabase = await createClient()

    const { error } = await supabase.auth.resend({
        type: 'signup',
        email: parsedEmail.data,
    })

    if (error) {
        return { error: error.message || 'Gagal mengirim ulang email verifikasi.' }
    }

    return { success: true }
}

export async function forgotPassword(prevState: any, formData: FormData) {
    const supabase = await createClient()

    const parsedEmail = z.string().trim().email('Format email tidak valid.').safeParse(formData.get('email'))

    if (!parsedEmail.success) {
        return { error: parsedEmail.error.issues[0].message }
    }

    const { error } = await supabase.auth.resetPasswordForEmail(parsedEmail.data, {
        redirectTo: `${process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000'}/auth/callback-reset`,
    })

    if (error) {
        return { error: 'Gagal mengirim email reset password.' }
    }

    return { success: true, email: parsedEmail.data }
}

export async function resetPassword(prevState: any, formData: FormData) {
    const supabase = await createClient()

    const parsed = resetPasswordSchema.safeParse({
        password: formData.get('password'),
        passwordConfirm: formData.get('passwordConfirm'),
    })

    if (!parsed.success) {
        return { error: parsed.error.issues[0].message }
    }

    if (parsed.data.password !== parsed.data.passwordConfirm) {
        return { error: 'Konfirmasi kata sandi tidak cocok.' }
    }

    const { error } = await supabase.auth.updateUser({ password: parsed.data.password })

    if (error) {
        return { error: error.message || 'Gagal mengubah kata sandi.' }
    }

    await createAuditLog('UPDATE', 'auth', 'Pengguna berhasil mereset kata sandi')

    return { success: true }
}
