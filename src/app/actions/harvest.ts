"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";
import { createAuditLog } from "@/lib/audit";
import { requireAuth } from "@/lib/auth-guard";
import { decryptFieldSafe, encryptField, signPayload, verifyPayloadSignature } from "@/lib/crypto";

function buildHarvestSigningPayload(params: {
    livestock_id: string;
    customer_name: string;
    selling_price: number;
    live_weight: number;
    carcass_weight: number | null;
    harvest_type: string;
    harvest_date: string;
    signed_by: string;
}) {
    return {
        livestock_id: params.livestock_id,
        customer_name: params.customer_name,
        selling_price: Number(params.selling_price),
        live_weight: Number(params.live_weight),
        carcass_weight: params.carcass_weight !== null && params.carcass_weight !== undefined ? Number(params.carcass_weight) : null,
        harvest_type: params.harvest_type,
        harvest_date: new Date(params.harvest_date).toISOString(),
        signed_by: params.signed_by,
    };
}

/**
 * Verifikasi Tanda Tangan Digital (RSA-2048-PSS) secara real-time untuk satu transaksi panen.
 * Menjamin Non-Repudiation & mendeteksi tampering pada harga jual, berat, atau nama pembeli di DB.
 */
export async function verifyHarvestRecordSignature(recordId: string) {
    const ctx = await requireAuth();
    const supabase = await createClient();

    let query = supabase
        .from("harvest_records")
        .select("id, livestock_id, customer_name, selling_price, live_weight, carcass_weight, harvest_type, harvest_date, digital_signature, signature_payload_hash, signed_by, signed_at, user_id")
        .eq("id", recordId);

    if (ctx.role !== "admin") {
        query = query.eq("user_id", ctx.effectiveUserId);
    }

    const { data: record, error } = await query.single();

    if (error || !record) {
        return { valid: false, status: "NOT_FOUND", message: "Transaksi tidak ditemukan atau akses ditolak." };
    }

    if (!record.digital_signature || !record.signed_by) {
        return { valid: false, status: "UNSIGNED", message: "Transaksi legacy (belum memiliki tanda tangan digital)." };
    }

    const decryptedCustomer = decryptFieldSafe(record.customer_name, "harvest_records:customer_name");
    const payload = buildHarvestSigningPayload({
        livestock_id: record.livestock_id,
        customer_name: decryptedCustomer,
        selling_price: record.selling_price,
        live_weight: record.live_weight,
        carcass_weight: record.carcass_weight,
        harvest_type: record.harvest_type,
        harvest_date: record.harvest_date,
        signed_by: record.signed_by,
    });

    const isValid = verifyPayloadSignature(payload, record.digital_signature);

    return {
        valid: isValid,
        status: isValid ? "VALID" : "TAMPERED",
        payloadHash: record.signature_payload_hash,
        signedAt: record.signed_at,
        message: isValid
            ? "Tanda tangan digital RSA-2048-PSS VALID. Data transaksi asli dan tidak pernah dimodifikasi."
            : "PERINGATAN TAMPERING: Tanda tangan digital TIDAK COCOK! Data harga, berat, atau pembeli telah berubah di database.",
    };
}

export async function processHarvest(formData: FormData) {
    const ctx = await requireAuth();
    const supabase = await createClient();
    const effectiveUserId = ctx.effectiveUserId;

    const customerName = formData.get("customer_name") as string;
    const harvestType = formData.get("harvest_type") as string || "potong";
    const livestockDataRaw = formData.get("livestock_data") as string;
    
    if (!livestockDataRaw || !customerName) {
        throw new Error("Data ternak dan Nama Pembeli tidak lengkap.");
    }

    let livestockData: { id: string, price: number, weight: number }[] = [];
    try {
        livestockData = JSON.parse(livestockDataRaw);
    } catch (e) {
        throw new Error("Format data ternak tidak valid.");
    }

    if (livestockData.length === 0) {
        throw new Error("Tidak ada ternak yang dipilih untuk diproses.");
    }

    // Carcass weight is only relevant for "potong" (which is currently restricted to single processing anyway)
    const rawCarcassWeight = formData.get("carcass_weight") as string || "";
    const carcassWeight = rawCarcassWeight ? parseFloat(rawCarcassWeight.replace(/,/g, ".")) : null;

    if (harvestType === "potong" && !carcassWeight) {
        throw new Error("Mohon lengkapi Berat Karkas untuk tipe Potong.");
    }

    // Handle Camera or Gallery files for Live Photo (Shared for Bulk)
    const livePhotoCamera = formData.get("live_photo_camera") as File;
    const livePhotoGallery = formData.get("live_photo_gallery") as File;
    const livePhoto = (livePhotoCamera && livePhotoCamera.size > 0) ? livePhotoCamera : livePhotoGallery;

    // Handle Camera or Gallery files for Carcass Photo
    const carcassPhotoCamera = formData.get("carcass_photo_camera") as File;
    const carcassPhotoGallery = formData.get("carcass_photo_gallery") as File;
    const carcassPhoto = (carcassPhotoCamera && carcassPhotoCamera.size > 0) ? carcassPhotoCamera : carcassPhotoGallery;

    let livePhotoUrl = null;
    let carcassPhotoUrl = null;

    // Upload live photo (once for all items in this transaction batch)
    if (livePhoto && livePhoto.size > 0) {
        const fileExt = livePhoto.name.split('.').pop();
        // Use the first livestock ID as the representative name to avoid massive filenames
        const fileName = `live_${livestockData[0].id}_${Date.now()}.${fileExt}`;
        const { error: uploadError } = await supabase.storage
            .from('harvest_photos')
            .upload(fileName, livePhoto);
        
        if (uploadError) throw new Error("Gagal mengunggah foto hidup: " + uploadError.message);
        
        const { data: publicUrlData } = supabase.storage.from('harvest_photos').getPublicUrl(fileName);
        livePhotoUrl = publicUrlData.publicUrl;
    }

    // Upload carcass photo (only if provided and for potong)
    if (harvestType === 'potong' && carcassPhoto && carcassPhoto.size > 0) {
        const fileExt = carcassPhoto.name.split('.').pop();
        const fileName = `carcass_${livestockData[0].id}_${Date.now()}.${fileExt}`;
        const { error: uploadError } = await supabase.storage
            .from('harvest_photos')
            .upload(fileName, carcassPhoto);
        
        if (uploadError) throw new Error("Gagal mengunggah foto karkas: " + uploadError.message);
        
        const { data: publicUrlData } = supabase.storage.from('harvest_photos').getPublicUrl(fileName);
        carcassPhotoUrl = publicUrlData.publicUrl;
    }

    // Fetch all livestock information (strict tenant isolation: filter user_id)
    const idsToFetch = livestockData.map(l => l.id);
    const { data: livestocks, error: fetchError } = await supabase
        .from('livestocks')
        .select('id, cage_id')
        .eq('user_id', effectiveUserId)
        .in('id', idsToFetch);
    
    if (fetchError || !livestocks || livestocks.length === 0) {
        throw new Error("Gagal memverifikasi ternak dari database atau ternak bukan milik peternakan Anda.");
    }

    // Process each livestock individually
    for (const data of livestockData) {
        if (!Number.isFinite(data.price) || data.price < 0 || !Number.isFinite(data.weight) || data.weight <= 0) {
            throw new Error("Nilai harga jual dan berat ternak harus berupa angka valid.");
        }
        const livestock = livestocks.find(l => l.id === data.id);
        if (!livestock) continue; // Skip if not found

        // 1. Insert HarvestRecord (Enkripsi AES-256-GCM + Tanda Tangan Digital RSA-2048-PSS)
        const harvestDateIso = new Date().toISOString();
        const encryptedCustomerName = encryptField(customerName, "harvest_records:customer_name");
        const finalCarcassWeight = carcassWeight !== null && harvestType === 'potong' ? carcassWeight : null;

        const signingPayload = buildHarvestSigningPayload({
            livestock_id: data.id,
            customer_name: customerName,
            selling_price: data.price,
            live_weight: data.weight,
            carcass_weight: finalCarcassWeight,
            harvest_type: harvestType,
            harvest_date: harvestDateIso,
            signed_by: ctx.userId,
        });
        const { signature, payloadHash } = signPayload(signingPayload);

        const recordPayload: any = {
            livestock_id: data.id,
            live_weight: data.weight, // from frontend calculation (borongan or satuan)
            customer_name: encryptedCustomerName,
            selling_price: data.price, // from frontend calculation (borongan or satuan)
            harvest_date: harvestDateIso,
            status: 'completed',
            live_photo_url: livePhotoUrl,
            carcass_photo_url: carcassPhotoUrl,
            harvest_type: harvestType,
            user_id: effectiveUserId,
            is_encrypted: true,
            digital_signature: signature,
            signature_payload_hash: payloadHash,
            signed_by: ctx.userId,
            signed_at: harvestDateIso,
        };

        if (finalCarcassWeight !== null) {
            recordPayload.carcass_weight = finalCarcassWeight;
        }

        const { error: insertError } = await supabase
            .from('harvest_records')
            .insert(recordPayload);
        
        if (insertError) {
            console.warn(`[HarvestAction] Attempting fallback insert without harvest_type for ${data.id}:`, insertError.message);
            // Fallback for missing 'harvest_type' column or strict NOT NULL on carcass_weight
            const fallbackPayload = { ...recordPayload };
            delete fallbackPayload.harvest_type;
            if (harvestType === 'jual_hidup') {
                fallbackPayload.carcass_weight = 0; // fallback to 0 if db complains about null
            }
            const { error: fallbackError } = await supabase
                .from('harvest_records')
                .insert(fallbackPayload);
                
            if (fallbackError) throw new Error(`Gagal menyimpan transaksi untuk ternak ${data.id}: ` + fallbackError.message);
        }

        // 2. Update Livestock status
        const { error: updateLvError } = await supabase
            .from('livestocks')
            .update({ status: 'sold' })
            .eq('id', data.id);
        
        if (updateLvError) throw new Error(`Gagal memperbarui status ternak ${data.id}: ` + updateLvError.message);

        // 3. Update Cage occupancy
        if (livestock.cage_id) {
            const { data: cage } = await supabase.from('cages').select('current_occupancy').eq('id', livestock.cage_id).single();
            if (cage && cage.current_occupancy > 0) {
                await supabase.from('cages').update({ current_occupancy: cage.current_occupancy - 1 }).eq('id', livestock.cage_id);
            }
        }
    }

    // 4. Record Audit Log for the batch
    await createAuditLog(
        'CREATE', 
        'harvest', 
        `Memproses ${harvestType} untuk ${livestockData.length} ekor ternak kepada pembeli: ${customerName}`,
        undefined,
        null,
        livestockData
    );

    // Revalidate paths to reflect updates instantly
    revalidatePath('/harvest');
    revalidatePath('/livestock');
    revalidatePath('/cages');
    revalidatePath('/dashboard');
}
