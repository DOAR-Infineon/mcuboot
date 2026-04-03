/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * XIP Encryption Library -- Default Decryption (Software AES-CTR)
 *
 * Provides a __weak boot_decrypt_xip() using bootutil AES-CTR wrappers.
 * Works with any crypto backend (tinycrypt, mbedTLS, PSA).
 *
 * Platforms with hardware crypto (e.g., SMIF) should provide a strong
 * override for better performance.
 */

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_ENC_IMAGES_XIP)

#include <stdint.h>
#include <string.h>
#include "bootutil/crypto/aes_ctr.h"
#include "flash_map_backend/flash_map_backend.h"
#include "xip_enc.h"

/*
 * Default (weak) boot_decrypt_xip -- software AES-CTR decryption.
 *
 * Retrieves key/IV from xip_enc_get_key() (populated by the validation
 * hook during ECIES unwrap). Builds AES-CTR nonce and decrypts buf in-place.
 *
 * Nonce format (edgeprotecttools-aligned):
 *   bits  0..31  = byte offset (little-endian)
 *   bits 32..127 = xip_iv[0:12]
 * Counter increments by 16 per AES block (raw byte offset).
 *
 * Platforms with hardware XIP decryption (e.g., Infineon SMIF) should
 * provide a strong override of this function.
 */
__attribute__((weak))
int boot_decrypt_xip(int image_index, const struct flash_area *fap,
                     uint32_t off, uint32_t sz, uint8_t *buf)
{
    bootutil_aes_ctr_context aes_ctr;
    uint8_t key[XIP_ENC_KEY_SIZE];
    uint8_t iv[XIP_ENC_IV_SIZE];
    uint8_t nonce[16];
    uint32_t blk_off;
    int rc;

    (void)fap;

    if (sz == 0u) {
        return 0;
    }

    /* Retrieve key/IV stored by boot_image_check_hook */
    if (xip_enc_get_key(image_index, key, iv) != 0) {
        return -1;
    }

    /* Build nonce: counter_LE32 || iv[0:12]  (edgeprotecttools format)
     *   bits 0..31  = byte offset (little-endian)
     *   bits 32..127 = xip_iv[0:12]
     */
    (void)memset(nonce, 0, sizeof(nonce));
    nonce[0] = (uint8_t)(off);
    nonce[1] = (uint8_t)(off >> 8);
    nonce[2] = (uint8_t)(off >> 16);
    nonce[3] = (uint8_t)(off >> 24);
    (void)memcpy(&nonce[4], iv, 12);

    bootutil_aes_ctr_init(&aes_ctr);
    rc = bootutil_aes_ctr_set_key(&aes_ctr, key);
    if (rc != 0) {
        bootutil_aes_ctr_drop(&aes_ctr);
        xip_enc_zeroize(key, sizeof(key));
        return -1;
    }

    blk_off = off & 0xfu;
    rc = bootutil_aes_ctr_encrypt(&aes_ctr, nonce, buf, sz, blk_off, buf);
    bootutil_aes_ctr_drop(&aes_ctr);

    /* Zeroize key from stack */
    xip_enc_zeroize(key, sizeof(key));

    return rc;
}

#endif /* MCUBOOT_ENC_IMAGES_XIP */
