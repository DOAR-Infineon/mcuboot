# Porting how-to

This document describes the requirements and necessary steps required to port
`MCUboot` to a new target `OS`.

# Requirements

* `MCUboot` requires a configuration file, which can be included as
   mcuboot_config/mcuboot_config.h, which configures various options
   (that begin with MCUBOOT_).

* `MCUboot` requires that the target provides a `flash` API with ability to
  get the flash's minimum write size, and read/write/erase individual sectors.

* `MCUboot` doesn't bundle a cryptographic library, which means the target
  OS must already have it bundled. The supported libraries at the moment are
  either `Mbed TLS` or the set `tinycrypt` + `Mbed TLS` (where `Mbed TLS` is
  used to provide functionality not existing in `tinycrypt`).

# Steps to port

## Main app and calling the bootloader

From the perspective of the target OS, the bootloader can be seen as a library,
so an entry point must be provided. This is likely a typical `app` for the
target OS, and it must call the following function to run the bootloader:

```c
int boot_go(struct boot_rsp *rsp);
```

This function is located at `boot/bootutil/loader.c` and receives a `struct
boot_rsp` pointer. The `struct boot_rsp` is defined as:

```c
struct boot_rsp {
    /** A pointer to the header of the image to be executed. */
    const struct image_header *br_hdr;

    /**
     * The flash offset of the image to execute.  Indicates the position of
     * the image header.
     */
    uint8_t br_flash_id;
    uint32_t br_image_addr;
};
```

After running the management functions of the bootloader, `boot_go` returns
an initialized `boot_rsp` which has pointers to the location of the image
where the target firmware is located which can be used to jump to.

## Configuration file

You must provide a file, mcuboot_config/mcuboot_config.h. This is
included by several files in the "library" portion of MCUboot; it
provides preprocessor definitions that configure the library's
build.

See the file samples/mcuboot_config/mcuboot_config.template.h for a
starting point and more information. This is a good place to convert
settings in your environment's configuration system to those required
by MCUboot. For example, Mynewt uses MYNEWT_VAL() and Zephyr uses
Kconfig; these configuration systems are converted to MCUBOOT_ options
in the following files:

- boot/zephyr/include/mcuboot_config/mcuboot_config.h
- boot/mynewt/mcuboot_config/include/mcuboot_config/mcuboot_config.h

## Flash Map

The bootloader requires to be able to address flash regions where the code
for MCUboot and images of applications are stored, in system-agnostic way.
For that purpose the MCUboot uses ID, which is integer (uint8_t) number
that should uniquely identify each flash region.
Such flash regions are served by object of `const struct flash_area` type while
layout of these objects is gathered under `flash_map`.
The common code of MCUboot, that is non-system specific, does not directly
access contents of that object and never modifies it, instead it calls
`flash_area_` API to perform any actions on that object.
This way systems are free to implement internal logic of flash map or define
`struct flash_area` as they wish; the only restriction is that ID should be
uniquely tied to region characterized by device, offset and size.

Changes to common MCUboot code should not affect system specific internals
of flash map, on the other side system specific code, within MCUboot, is
is not restricted from directly accessing `struct flash_area` elements.


An implementation of `struct flash_area` may take form of:
```c
struct flash_area {
    uint8_t  fa_id;         /** The slot/scratch identification */
    uint8_t  fa_device_id;  /** The device id (usually there's only one) */
    uint16_t pad16;
    uint32_t fa_off;        /** The flash offset from the beginning */
    uint32_t fa_size;       /** The size of this sector */
};
```
The above example of structure hold all information that is currently required
by MCUboot, although the MCUboot will not be trying to access them directly,
instead a system is required to provide following mandatory getter functions:

```c
/*< Obtains ID of the flash area characterized by `fa` */
int     flash_area_get_id(const struct flash_area *fa);
/*< Obtains ID of a device the flash area `fa` described region resides on */
int     flash_area_get_device_id(const struct flash_area *fa)
/*< Obtains offset, from the beginning of a device, the flash area described
 * region starts at */
uint32_t flash_area_get_off(const struct flash_area *fa)
/*< Obtains size, from the offset, of the flash area `fa` characterized region */
uint32_t flash_area_get_size(const struct flash_area *fa)

```

The MCUboot common code uses following defines that should be defined by system
specific header files and are used to identify destination of flash area by ID:

```c
/* Independent from multiple image boot */
#define FLASH_AREA_BOOTLOADER         0
#define FLASH_AREA_IMAGE_SCRATCH      3
```
```c
/* Flash area IDs of the first image in case of multiple images */
#define FLASH_AREA_IMAGE_PRIMARY      1
#define FLASH_AREA_IMAGE_SECONDARY    2
```
```c
/* Flash area IDs of the second image in case of multiple images */
#define FLASH_AREA_IMAGE_PRIMARY      5
#define FLASH_AREA_IMAGE_SECONDARY    6
```

The numbers, given above, are provided as an example and depend on system
implementation.

The main, also required, set of API functions that perform operations on
flash characterized by `struct flash_area` objects is as follows:

```c
/*< Opens the area for use. id is one of the `fa_id`s */
int      flash_area_open(uint8_t id, const struct flash_area **);
void     flash_area_close(const struct flash_area *);
/*< Reads `len` bytes of flash memory at `off` to the buffer at `dst` */
int      flash_area_read(const struct flash_area *, uint32_t off, void *dst,
                         uint32_t len);
/*< Writes `len` bytes of flash memory at `off` from the buffer at `src` */
int      flash_area_write(const struct flash_area *, uint32_t off,
                          const void *src, uint32_t len);
/*< Erases `len` bytes of flash memory at `off` */
int      flash_area_erase(const struct flash_area *, uint32_t off, uint32_t len);
/*< Returns this `flash_area`s alignment */
uint32_t flash_area_align(const struct flash_area *);
/*< What is value is read from erased flash bytes. */
uint8_t  flash_area_erased_val(const struct flash_area *);
/*< Given flash area ID, return info about sectors within the area. */
int      flash_area_get_sectors(int fa_id, uint32_t *count,
                                struct flash_sector *sectors);
/*< Returns the `fa_id` for slot, where slot is 0 (primary) or 1 (secondary).
    `image_index` (0 or 1) is the index of the image. Image index is
    relevant only when multi-image support support is enabled */
int      flash_area_id_from_multi_image_slot(int image_index, int slot);
/*< Returns the slot (0 for primary or 1 for secondary), for the supplied
    `image_index` and `area_id`. `area_id` is unique and is represented by
    `fa_id` in the `flash_area` struct. */
int      flash_area_id_to_multi_image_slot(int image_index, int area_id);
```

---
***Note***

*As of writing, it is possible that MCUboot will open a flash area multiple times simultaneously (through nested calls to `flash_area_open`). As a result, MCUboot may call `flash_area_close` on a flash area that is still opened by another part of MCUboot. As a workaround when porting, it may be necessary to implement a counter of the number of times a given flash area has been opened by MCUboot. The `flash_area_close` implementation should only fully deinitialize the underlying flash area when the open counter is decremented to 0. See [this GitHub PR](https://github.com/mcu-tools/mcuboot/pull/894/) for a more detailed discussion.*

---

## Memory management for Mbed TLS

`Mbed TLS` employs dynamic allocation of memory, making use of the pair
`calloc/free`. If `Mbed TLS` is to be used for crypto, your target RTOS
needs to provide this pair of function.

To configure the what functions are called when allocating/deallocating
memory `Mbed TLS` uses the following call:

```
int mbedtls_platform_set_calloc_free (void *(*calloc_func)(size_t, size_t),
                                      void (*free_func)(void *));
```

For reference see [Mbed TLS platform.h](https://tls.mbed.org/api/platform_8h.html).
If your system already provides functions with compatible signatures, those can
be used directly here, otherwise create new functions that glue to your
`calloc/free` implementations.

## XIP Encryption Porting

Some platforms provide hardware-assisted execute-in-place (XIP) crypto engines
that transparently decrypt code as it is fetched from external flash (e.g.,
Infineon SMIF with on-the-fly decryption). On these platforms the encryption
and decryption of image payloads is handled entirely by the hardware crypto
region rather than by MCUboot's software encryption path. This section
describes how to port MCUboot for such a configuration.

### When to use

Use this porting path when the target platform has a hardware XIP crypto engine
that can transparently decrypt code execution from encrypted external flash.
Typical examples include SPI flash controllers with built-in AES decryption
regions, where the CPU fetches plaintext instructions while the flash itself
stores ciphertext.

### Required definitions

The following preprocessor definitions must be set in the platform's
`mcuboot_config/mcuboot_config.h`:

* **`MCUBOOT_ENC_IMAGES_XIP`** --- Enables the XIP encryption flow in MCUboot.
  This tells the bootloader that image encryption is managed by the platform
  hardware rather than by MCUboot's built-in software encryption.

* **`MCUBOOT_IMAGE_ACCESS_HOOKS`** --- Enables the image access hook interface
  so that the platform can override image validation with its own hardware-aware
  implementation.

---
***Note***

*`MCUBOOT_ENC_IMAGES` is **not** defined in this configuration. The platform
handles encryption independently of MCUboot's software encryption path. Swap
operations perform raw byte copies with no encryption or decryption applied
during the swap itself.*

---

### Functions the platform must provide

#### Image validation hook

```c
fih_ret boot_image_check_hook(int img_index, int slot);
```

Called by MCUboot during image validation in place of the default validation
logic. The platform implementation must:

1. Open the flash area for the given slot.
2. Read the image header.
3. Extract the encryption key from the ECIES TLV in the image trailer.
4. Program the hardware crypto engine with the extracted key.
5. Compute and verify the image hash, decrypting the payload through the
   hardware crypto engine during the read.
6. Verify the image signature.

The function returns one of the following values:

* `FIH_SUCCESS` --- the image is valid.
* `FIH_FAILURE` --- the image is invalid.
* `FIH_BOOT_HOOK_REGULAR` --- fall through to MCUboot's default validation.

The hook must handle both encrypted and non-encrypted images. When no ECIES
TLV is present the image should be treated as unencrypted and validated
without programming the hardware crypto engine.

#### Populating the boot response with key material

```c
void boot_xip_populate_rsp(int img_index, struct boot_rsp *rsp);
```

Called by MCUboot after `fill_rsp()` completes. The platform implementation
copies the encryption key and initialisation vector (IV) that were extracted
during validation into the boot response structure:

* `rsp->xip_key` --- the AES key used by the hardware crypto region.
* `rsp->xip_iv` --- the IV / nonce used by the hardware crypto region.

These fields are consumed later by the platform's main bootloader function
to configure the hardware before jumping to the application.

#### Hardware crypto region setup

After `boot_go` returns, the platform's main bootloader function must
configure the hardware crypto regions for each image using the key and IV
stored in `boot_rsp`. A typical sequence is:

1. For each image, read `rsp->xip_key` and `rsp->xip_iv`.
2. Program the hardware crypto engine's per-region registers (base address,
   size, key, IV).
3. Enable the crypto regions permanently so that subsequent code fetches from
   external flash are decrypted transparently.

This step is platform-specific and lives outside of MCUboot's common code.

### Key design constraints

* **No software encryption during swap** --- because `MCUBOOT_ENC_IMAGES` is
  not defined, swap operations copy raw bytes. The ciphertext is moved as-is
  between primary and secondary slots.

* **Keys are not persisted to flash** --- the encryption key and IV are
  re-extracted from the ECIES TLV in the image trailer on every boot and
  after every swap. There is no key storage outside of the `boot_rsp`
  structure passed to the platform at boot time.

* **Mixed image support** --- the `boot_image_check_hook` implementation must
  handle both encrypted and non-encrypted images. An image without an ECIES
  TLV should be validated using the normal (unencrypted) hash and signature
  checks, returning `FIH_SUCCESS` or `FIH_BOOT_HOOK_REGULAR` as appropriate.
