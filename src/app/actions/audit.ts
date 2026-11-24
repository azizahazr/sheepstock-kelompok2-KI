'use server'

import { createClient } from '@/lib/supabase/server'
import { revalidatePath } from 'next/cache'
import { buildAuditHashInput, createAuditLog } from '@/lib/audit'
import { requireRole } from '@/lib/auth-guard'
import { sha256, verifyPayloadSignature } from '@/lib/crypto'

export type AuditChainVerificationResult = {
    isValid: boolean
    totalChecked: number
    brokenLogIds: string[]
    message: string
}

/**
 * Memverifikasi seluruh rantai Hash-Chained Audit Log (SHA-256 + RSA-PSS Signature).
 * Jika ada 1 baris log yang diubah/dihapus langsung di database, rantai langsung terdeteksi putus!
 */
export async function verifyAuditLogChain(): Promise<AuditChainVerificationResult> {
    const ctx = await requireRole(['owner', 'admin'])
    const supabase = await createClient()

    let query = supabase
        .from('audit_logs')
        .select('id, tenant_id, user_id, action, entity_type, entity_id, description, created_at, prev_hash, current_hash, log_signature')
        .not('current_hash', 'is', null)
        .order('created_at', { ascending: true })

    if (ctx.role !== 'admin') {
        query = query.eq('tenant_id', ctx.effectiveUserId)
    }

    const { data: logs, error } = await query

    if (error) {
        throw new Error('Gagal membaca audit logs untuk verifikasi: ' + error.message)
    }

    if (!logs || logs.length === 0) {
        return {
            isValid: true,
            totalChecked: 0,
            brokenLogIds: [],
            message: 'Belum ada log berantai (hash-chained) yang tercatat.',
        }
    }

    const brokenLogIds: string[] = []
    const lastHashByTenant: Record<string, string> = {}

    for (const log of logs) {
        const tenantKey = log.tenant_id || 'default'
        const expectedPrev = lastHashByTenant[tenantKey] ?? 'GENESIS'

        // 1. Cek keterhubungan prev_hash
        const prevValid = log.prev_hash === expectedPrev

        // 2. Hitung ulang SHA-256 current_hash dari data log aktual di DB
        const recomputedHash = sha256(
            buildAuditHashInput({
                prev_hash: log.prev_hash || '',
                tenant_id: log.tenant_id || '',
                user_id: log.user_id || '',
                action: log.action,
                entity_type: log.entity_type,
                entity_id: log.entity_id ?? null,
                description: log.description ?? '',
                created_at: new Date(log.created_at).toISOString(),
            })
        )
        const hashValid = recomputedHash === log.current_hash

        // 3. Verifikasi tanda tangan digital RSA-PSS (jika ada)
        let sigValid = true
        if (log.log_signature) {
            sigValid = verifyPayloadSignature(
                {
                    prev_hash: log.prev_hash,
                    current_hash: log.current_hash,
                    tenant_id: log.tenant_id,
                    user_id: log.user_id,
                    action: log.action,
                    entity_type: log.entity_type,
                    created_at: new Date(log.created_at).toISOString(),
                },
                log.log_signature
            )
        }

        if (!prevValid || !hashValid || !sigValid) {
            brokenLogIds.push(log.id)
        }

        lastHashByTenant[tenantKey] = log.current_hash
    }

    const isValid = brokenLogIds.length === 0
    return {
        isValid,
        totalChecked: logs.length,
        brokenLogIds,
        message: isValid
            ? `Integritas UTUH: Seluruh ${logs.length} entri Audit Log valid (SHA-256 Hash Chain & RSA-PSS Signature cocok).`
            : `PERINGATAN TAMPERING: Ditemukan ${brokenLogIds.length} dari ${logs.length} entri log yang tidak cocok/dimodifikasi!`,
    }
}

export async function restoreCheckpoint(logId: string) {
    // 1. Verifikasi Role & Tenant Context (RBAC ketat)
    const ctx = await requireRole(['owner', 'admin'])
    const supabase = await createClient()

    // 2. Fetch the log
    const { data: log, error: logError } = await supabase
        .from('audit_logs')
        .select('*')
        .eq('id', logId)
        .single()

    if (logError || !log) {
        throw new Error("Log tidak ditemukan.")
    }

    // Isolasi tenant: Owner hanya boleh restore log milik peternakannya sendiri
    if (ctx.role === 'owner' && log.tenant_id && log.tenant_id !== ctx.effectiveUserId) {
        throw new Error("Otorisasi ditolak: Anda hanya dapat melakukan restore pada log milik peternakan Anda sendiri.")
    }

    if (!log.old_data && log.action !== 'CREATE') {
        throw new Error("Log ini tidak memiliki data checkpoint (old_data) sehingga tidak dapat di-restore.")
    }

    const entityType = log.entity_type
    const entityId = log.entity_id

    // Whitelist tabel yang diizinkan untuk restore (cegah arbitrary table write)
    const tableMap: Record<string, string> = {
        'livestock': 'livestocks',
        'cage': 'cages',
        'cages': 'cages',
        'profiles': 'profiles'
    }

    const tableName = tableMap[entityType]
    if (!tableName) {
        throw new Error(`Modul '${entityType}' tidak didukung untuk restore checkpoint.`)
    }

    // 3. Process Restore Based on Action
    try {
        if (log.action === 'UPDATE') {
            if (!entityId || !log.old_data) throw new Error("ID atau Data lama tidak valid.")

            const payload = { ...log.old_data }

            const { error: updateError } = await supabase
                .from(tableName)
                .update(payload)
                .eq('id', entityId)

            if (updateError) throw updateError

            await createAuditLog(
                'UPDATE',
                entityType,
                `RESTORE: Mengembalikan data ke kondisi sebelum diubah pada ${new Date(log.created_at).toLocaleString('id-ID')}`,
                entityId,
                log.new_data,
                log.old_data
            )
        }
        else if (log.action === 'DELETE') {
            if (!log.old_data) throw new Error("Data lama tidak valid.")

            const payload = { ...log.old_data }

            const { error: insertError } = await supabase
                .from(tableName)
                .insert(payload)

            if (insertError) throw insertError

            await createAuditLog(
                'CREATE',
                entityType,
                `RESTORE: Mengembalikan data yang telah dihapus pada ${new Date(log.created_at).toLocaleString('id-ID')}`,
                payload.id,
                null,
                payload
            )
        }
        else if (log.action === 'CREATE') {
            if (!entityId) throw new Error("ID tidak valid.")

            const { error: deleteError } = await supabase
                .from(tableName)
                .delete()
                .eq('id', entityId)

            if (deleteError) throw deleteError

            await createAuditLog(
                'DELETE',
                entityType,
                `RESTORE: Menghapus data yang dibuat pada ${new Date(log.created_at).toLocaleString('id-ID')}`,
                entityId,
                log.new_data,
                null
            )
        }
    } catch (e: any) {
        if (e.code === '23503' || e.message?.includes('foreign key constraint')) {
            throw new Error(`Gagal melakukan restore: Data terkait sudah tidak ada atau akan menyebabkan konflik (Foreign Key Constraint).`)
        }
        throw new Error(`Gagal melakukan restore: ${e.message}`)
    }

    revalidatePath('/settings/audit-logs')
    revalidatePath('/dashboard')
    revalidatePath('/cages')
    revalidatePath('/livestock')
    revalidatePath('/settings/users')
}
