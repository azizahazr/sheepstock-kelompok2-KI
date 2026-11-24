import { createClient } from '@/lib/supabase/server';
import { sha256, signPayload } from '@/lib/crypto';

export type AuditAction = 'CREATE' | 'UPDATE' | 'DELETE' | 'LOGIN' | 'LOGOUT' | 'OTHER';

export function buildAuditHashInput(params: {
    prev_hash: string;
    tenant_id: string;
    user_id: string;
    action: string;
    entity_type: string;
    entity_id: string | null;
    description: string;
    created_at: string;
}): string {
    return [
        params.prev_hash,
        params.tenant_id,
        params.user_id,
        params.action,
        params.entity_type,
        params.entity_id ?? '',
        params.description ?? '',
        params.created_at,
    ].join('|');
}

export async function createAuditLog(
    action: AuditAction,
    entityType: string,
    description: string,
    entityId?: string,
    oldData?: any,
    newData?: any
) {
    const supabase = await createClient();

    // Get current user
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
        console.error('Audit Log failed: No authenticated user');
        return { success: false, error: 'User not authenticated' };
    }

    try {
        // Resolve tenant_id (owner_id jika staff, atau user.id jika owner/admin)
        const { data: profile } = await supabase
            .from('profiles')
            .select('role, owner_id')
            .eq('id', user.id)
            .single();

        const tenantId =
            profile?.role === 'staff' && profile?.owner_id ? profile.owner_id : user.id;

        // Ambil current_hash dari log terakhir milik tenant ini untuk Hash Chaining
        const { data: latestLog } = await supabase
            .from('audit_logs')
            .select('current_hash')
            .eq('tenant_id', tenantId)
            .not('current_hash', 'is', null)
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        const prevHash = latestLog?.current_hash || 'GENESIS';
        const createdAt = new Date().toISOString();

        const hashInput = buildAuditHashInput({
            prev_hash: prevHash,
            tenant_id: tenantId,
            user_id: user.id,
            action,
            entity_type: entityType,
            entity_id: entityId ?? null,
            description,
            created_at: createdAt,
        });

        const currentHash = sha256(hashInput);

        // Tanda tangani hash log menggunakan RSA-2048-PSS untuk menjamin integritas & non-repudiation
        let logSignature: string | null = null;
        try {
            const signed = signPayload({
                prev_hash: prevHash,
                current_hash: currentHash,
                tenant_id: tenantId,
                user_id: user.id,
                action,
                entity_type: entityType,
                created_at: createdAt,
            });
            logSignature = signed.signature;
        } catch (sigErr) {
            console.warn('Audit log signature skipped (keys not configured):', sigErr);
        }

        const { error } = await supabase.from('audit_logs').insert({
            user_id: user.id,
            tenant_id: tenantId,
            action,
            entity_type: entityType,
            description,
            created_at: createdAt,
            prev_hash: prevHash,
            current_hash: currentHash,
            log_signature: logSignature,
            ...(entityId && { entity_id: entityId }),
            ...(oldData && { old_data: oldData }),
            ...(newData && { new_data: newData }),
        });

        if (error) {
            console.error('Failed to create audit log:', error);
            return { success: false, error };
        }

        return { success: true, currentHash };
    } catch (e) {
        console.error('Audit Log exception:', e);
        return { success: false, error: e };
    }
}
