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
 * hook during ECIES unwrap). Builds AES-CTR nonce from IV + offset-based
 * counter and decrypts buf in-place.
 *
 * Counter = off / 16 (absolute flash area offset).
 * Nonce = IV[0..11] || counter_be32.
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
    uint32_t ctr;
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

    /* Build nonce: IV[0..11] || counter(big-endian) */
    (void)memcpy(nonce, iv, 16);
    ctr = off >> 4;
    nonce[12] = (uint8_t)(ctr >> 24);
    nonce[13] = (uint8_t)(ctr >> 16);
    nonce[14] = (uint8_t)(ctr >> 8);
    nonce[15] = (uint8_t)(ctr);

    bootutil_aes_ctr_init(&aes_ctr);
    rc = bootutil_aes_ctr_set_key(&aes_ctr, key);
    if (rc != 0) {
        bootutil_aes_ctr_drop(&aes_ctr);
        (void)memset(key, 0, sizeof(key));
        return -1;
    }

    blk_off = off & 0xfu;
    rc = bootutil_aes_ctr_encrypt(&aes_ctr, nonce, buf, sz, blk_off, buf);
    bootutil_aes_ctr_drop(&aes_ctr);

    /* Zeroize key from stack */
    (void)memset(key, 0, sizeof(key));

    return rc;
}

#endif /* MCUBOOT_ENC_IMAGES_XIP */
