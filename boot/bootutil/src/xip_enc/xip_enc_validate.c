/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * XIP Encryption Library - Default Image Validation Hook
 *
 * Provides a __weak boot_image_check_hook() that performs:
 *   1. SHA-256 hash over raw ciphertext (no decryption)
 *   2. ECDSA-P256 signature verification (mandatory for encrypted images)
 *   3. ECIES-P256 key unwrap (via xip_enc_ecies_unwrap)
 *
 * Platforms may override with a strong implementation for FIH hardening
 * or hardware-accelerated crypto.
 */

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_ENC_IMAGES_XIP) && defined(MCUBOOT_IMAGE_ACCESS_HOOKS)

#include <string.h>
#include <stdint.h>
#include "bootutil/bootutil.h"
#include "bootutil/image.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil_priv.h"

/* Forward declaration -- provided by each platform's flash_map_backend */
int flash_area_id_from_multi_image_slot(int image_index, int slot);
#include "bootutil/boot_hooks.h"
#include "bootutil/crypto/sha.h"
#include "flash_map_backend/flash_map_backend.h"
#include "xip_enc.h"

/*
 * Compute SHA-256 hash over raw flash: header + ciphertext + protected TLVs.
 * No decryption — hash covers the encrypted payload as-is.
 */
static int
xip_img_hash(const struct flash_area *fap,
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

        rc = flash_area_read(fap, off, buf, blk_sz);
        if (rc != 0) {
            bootutil_sha_drop(&sha_ctx);
            return -1;
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
 *   1. SHA-256 hash over raw ciphertext (no decryption)
 *   2. ECDSA-P256 signature verification (mandatory)
 *   3. ECIES-P256 key unwrap for hardware crypto setup
 *
 * Non-encrypted images are deferred to upstream (FIH_BOOT_HOOK_REGULAR).
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
     * Step 1: Hash raw ciphertext (no decryption)
     */
    uint8_t hash[32];
    rc = xip_img_hash(fap, &hdr, hash);
    if (rc != 0) {
        flash_area_close(fap);
        FIH_RET(fih_rc);
    }

    /*
     * Step 2: Verify SHA-256 against TLV
     */
    {
        struct image_tlv_iter it;
        uint32_t tlv_off;
        uint16_t tlv_len;
        uint8_t tlv_hash[32];

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
        if (memcmp(hash, tlv_hash, 32) != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }
    }

    /*
     * Step 3: Verify ECDSA signature (mandatory for encrypted images)
     */
    {
        struct image_tlv_iter it;
        uint32_t tlv_off;
        uint16_t tlv_len;
        uint8_t key_buf[256];
        uint8_t sig_buf[128];
        int key_id = -1;

        /* Find public key hash */
        rc = bootutil_tlv_iter_begin(&it, &hdr, fap, IMAGE_TLV_KEYHASH, false);
        if (rc == 0) {
            rc = bootutil_tlv_iter_next(&it, &tlv_off, &tlv_len, NULL);
            if (rc == 0 && tlv_len <= sizeof(key_buf)) {
                rc = flash_area_read(fap, tlv_off, key_buf, tlv_len);
                if (rc == 0) {
#ifndef MCUBOOT_HW_KEY
                    key_id = bootutil_find_key(key_buf, tlv_len);
#else
                    key_id = bootutil_find_key(img_index, key_buf, tlv_len);
#endif
                }
            }
        }

        if (key_id < 0) {
            /* No valid key — encrypted images MUST be signed */
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        /* Find and verify ECDSA signature */
        rc = bootutil_tlv_iter_begin(&it, &hdr, fap, IMAGE_TLV_ECDSA_SIG, false);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }
        rc = bootutil_tlv_iter_next(&it, &tlv_off, &tlv_len, NULL);
        if (rc != 0 || tlv_len > sizeof(sig_buf)) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }
        rc = flash_area_read(fap, tlv_off, sig_buf, tlv_len);
        if (rc != 0) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }

        FIH_DECLARE(sig_fih, FIH_FAILURE);
        FIH_CALL(bootutil_verify_sig, sig_fih, hash, sizeof(hash),
                 sig_buf, tlv_len, key_id);
        if (FIH_NOT_EQ(sig_fih, FIH_SUCCESS)) {
            flash_area_close(fap);
            FIH_RET(fih_rc);
        }
    }

    /*
     * Step 4: ECIES key unwrap (for hardware crypto setup after boot)
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
        if (rc != 0 || (tlv_len != 113 && tlv_len != 177)) {
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
        xip_enc_zeroize(key, 16);
        xip_enc_zeroize(iv, 16);
    }

    fih_rc = FIH_SUCCESS;
    flash_area_close(fap);
    FIH_RET(fih_rc);
}

#endif /* MCUBOOT_ENC_IMAGES_XIP && MCUBOOT_IMAGE_ACCESS_HOOKS */
