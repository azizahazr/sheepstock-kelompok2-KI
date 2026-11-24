import { createClient } from "@/lib/supabase/server"
import { HarvestClient } from "@/components/dashboard/harvest-client"
import { decryptFieldSafe, verifyPayloadSignature } from "@/lib/crypto"

export const dynamic = 'force-dynamic'

export default async function HarvestPage() {
    const supabase = await createClient()

    const { data: { user } } = await supabase.auth.getUser();
    let avatarUrl: string | null = null;
    let userName = "Admin";

    if (user) {
        const { data: profile } = await supabase.from("profiles").select("name").eq("id", user.id).single();
        if (profile?.name && profile.name !== "New Staff") userName = profile.name;
        else if (user.user_metadata?.full_name) userName = user.user_metadata.full_name;
        
        if (user.user_metadata?.avatar_url) avatarUrl = user.user_metadata.avatar_url;
    }

    // Fetch ALL active livestocks (not sold, not dead) so we can scan and sell any sheep via "Jual Hidup"
    const { data: allActiveLivestock } = await supabase
        .from("livestocks")
        .select(`
            *,
            cages ( name )
        `)
        .not("status", "eq", "sold")
        .not("status", "eq", "dead")
        .order("current_weight", { ascending: false });

    // Fetch harvest history & dekripsi field sensitif (AES-256-GCM)
    const { data: rawHarvestHistory } = await supabase
        .from("harvest_records")
        .select(`
            *,
            livestocks ( qr_code, type, gender )
        `)
        .order("harvest_date", { ascending: false });

    const harvestHistory = (rawHarvestHistory || []).map((record: any) => {
        const decryptedCustomer = decryptFieldSafe(record.customer_name, "harvest_records:customer_name");
        let signature_valid: boolean | null = null;
        if (record.digital_signature && record.signed_by) {
            signature_valid = verifyPayloadSignature(
                {
                    livestock_id: record.livestock_id,
                    customer_name: decryptedCustomer,
                    selling_price: Number(record.selling_price),
                    live_weight: Number(record.live_weight),
                    carcass_weight: record.carcass_weight !== null && record.carcass_weight !== undefined ? Number(record.carcass_weight) : null,
                    harvest_type: record.harvest_type,
                    harvest_date: new Date(record.harvest_date).toISOString(),
                    signed_by: record.signed_by,
                },
                record.digital_signature
            );
        }
        return {
            ...record,
            customer_name: decryptedCustomer,
            signature_valid,
        };
    });

    return (
        <HarvestClient
            allActiveLivestock={allActiveLivestock || []}
            harvestHistory={harvestHistory}
            avatarUrl={avatarUrl}
            userName={userName}
        />
    )
}
