/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * XIP Encryption Library - Default Image Validation Hook
 *
 * Provides a __weak boot_image_check_hook() that performs:
 *   1. ECIES-P256 key unwrap (via xip_enc_ecies_unwrap)
 *   2. SHA-256 hash verification over header + decrypted payload + protected TLVs
 *
 * Platforms may override with a strong implementation for FIH hardening
 * or hardware-accelerated crypto (e.g., Infineon SMIF + Secure Element).
 */

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_ENC_IMAGES_XIP) && defined(MCUBOOT_IMAGE_ACCESS_HOOKS)

#include <string.h>
#include <stdint.h>
#include "bootutil/bootutil.h"
#include "bootutil/image.h"
#include "bootutil/fault_injection_hardening.h"

/* Forward declaration -- provided by each platform's flash_map_backend */
int flash_area_id_from_multi_image_slot(int image_index, int slot);
#include "bootutil/boot_hooks.h"
#include "bootutil/crypto/sha.h"
#include "flash_map_backend/flash_map_backend.h"
#include "xip_enc.h"

/*
 * Compute SHA-256 hash over header + decrypted payload + protected TLVs.
 *
 * Mirrors bootutil_img_hash() logic but uses boot_decrypt_xip() for
 * payload decryption instead of boot_enc_decrypt().
 */
static int
xip_img_hash(int img_index, const struct flash_area *fap,
             const struct image_header *hdr, uint8_t *hash_out)
{
    bootutil_sha_context sha_ctx;
    uint32_t hdr_size;
    uint32_t payload_end;
    uint32_t hash_size;
    uint32_t off;
    uint32_t blk_sz;
    uint8_t buf[256];
    int rc;

    hdr_size = hdr->ih_hdr_size;
    payload_end = hdr_size + hdr->ih_img_size;
    hash_size = payload_end + hdr->ih_protect_tlv_size;

    bootutil_sha_init(&sha_ctx);

    for (off = 0; off < hash_size; off += blk_sz) {
        blk_sz = hash_size - off;
        if (blk_sz > sizeof(buf)) {
            blk_sz = sizeof(buf);
        }

        if ((off < hdr_size) && ((off + blk_sz) > hdr_size)) {
            blk_sz = hdr_size - off;
        }
        if ((off < payload_end) && ((off + blk_sz) > payload_end)) {
            blk_sz = payload_end - off;
        }

        rc = flash_area_read(fap, off, buf, blk_sz);
        if (rc != 0) {
            bootutil_sha_drop(&sha_ctx);
            return -1;
        }

        if (off >= hdr_size && off < payload_end) {
            rc = boot_decrypt_xip(img_index, fap, off, blk_sz, buf);
            if (rc != 0) {
                bootutil_sha_drop(&sha_ctx);
                return -1;
            }
        }

        bootutil_sha_update(&sha_ctx, buf, blk_sz);
    }

    bootutil_sha_finish(&sha_ctx, hash_out);
    bootutil_sha_drop(&sha_ctx);

    return 0;
}

/*
 * Default (weak) boot_image_check_hook for XIP encrypted images.
 *
 * Validates encrypted images by:
 *   1. ECIES-P256 key unwrap from IMAGE_TLV_ENC_EC256
 *   2. SHA-256 hash verification against IMAGE_TLV_SHA256
 *
 * Non-encrypted images are deferred to upstream (FIH_BOOT_HOOK_REGULAR).
 *
 * Platforms needing FIH hardening or hardware crypto should provide
 * a strong override of this function.
 */
__attribute__((weak))
fih_ret boot_image_check_hook(int img_index, int slot)
{
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    const struct flash_area *fap = NULL;
    struct image_header hdr;
    int rc;

    int fa_id = flash_area_id_from_multi_image_slot(img_index, slot);
    rc = flash_area_open(fa_id, &fap);
    if (rc != 0) {
        FIH_RET(fih_rc);
    }

    rc = flash_area_read(fap, 0, &hdr, sizeof(hdr));
    if (rc != 0 || hdr.ih_magic != IMAGE_MAGIC) {
        flash_area_close(fap);
        FIH_RET(fih_rc);
    }

    /* Non-encrypted images: let upstream handle */
    if (!IS_ENCRYPTED(&hdr)) {
        flash_area_close(fap);
        FIH_RET(FIH_BOOT_HOOK_REGULAR);
    }

    /*
     * Step 1: ECIES key unwrap
     */
    {
        struct image_tlv_iter it;
        uint32_t tlv_off;
        uint16_t tlv_len;
        uint8_t tlv_buf[180];
        uint8_t key[16], iv[16];

        rc = bootutil_tlv_iter_begin(&it, &hdr, fap, IMAGE_TLV_ENC_EC256, false);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        rc = bootutil_tlv_iter_next(&it, &tlv_off, &tlv_len, NULL);
        if (rc != 0 || tlv_len > sizeof(tlv_buf) || tlv_len < 113) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        rc = flash_area_read(fap, tlv_off, tlv_buf, tlv_len);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        rc = xip_enc_ecies_unwrap(tlv_buf, tlv_len, key, iv);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        xip_enc_store_key(img_index, key, iv);

        /* Zeroize from stack */
        memset(key, 0, 16);
        memset(iv, 0, 16);
    }

    /*
     * Step 2: SHA-256 hash verification
     */
    {
        uint8_t computed_hash[32];
        uint8_t tlv_hash[32];
        struct image_tlv_iter it;
        uint32_t tlv_off;
        uint16_t tlv_len;

        rc = xip_img_hash(img_index, fap, &hdr, computed_hash);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        rc = bootutil_tlv_iter_begin(&it, &hdr, fap, IMAGE_TLV_SHA256, false);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        rc = bootutil_tlv_iter_next(&it, &tlv_off, &tlv_len, NULL);
        if (rc != 0 || tlv_len != 32) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        rc = flash_area_read(fap, tlv_off, tlv_hash, 32);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        if (memcmp(computed_hash, tlv_hash, 32) != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }
    }

    fih_rc = FIH_SUCCESS;
    flash_area_close(fap);
    FIH_RET(fih_rc);
}

#endif /* MCUBOOT_ENC_IMAGES_XIP && MCUBOOT_IMAGE_ACCESS_HOOKS */
