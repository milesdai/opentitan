// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_kmac.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "kmac_regs.h"  // Generated.

OTTF_DEFINE_TEST_CONFIG();

/**
 * Struct to pack timeout values.
 */
typedef struct kmac_edn_timeout {
  uint16_t prescaler;
  uint16_t wait_timer;
  // Whether we expect timeout for hard-coded (`prescaler`, `wait_timer`) pairs
  bool timeout_expected;
} kmac_edn_timeout_t;


/**
 * KMAC test description.
 */
typedef struct kmac_test {
  dif_kmac_mode_kmac_t mode;
  dif_kmac_key_t key;

  const char *message;
  size_t message_len;

  const char *customization_string;
  size_t customization_string_len;

  const uint32_t digest[kKmacDigestLenMax];
  size_t digest_len;
  bool digest_len_is_fixed;
} kmac_test_t;

/**
 * A single KMAC example:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
 */
const kmac_test_t kKmacTestVector = {
    .mode = kDifKmacModeKmacLen256,
    .key =
        (dif_kmac_key_t){
            .share0 = {0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4f4c,
                       0x53525150, 0x57565554, 0x5b5a5958, 0x5f5e5d5c},
            .share1 = {0},
            .length = kDifKmacKeyLen256,
        },
    .message =
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
        "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
        "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
        "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
        "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
        "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
        "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
        "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
        "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
        "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
    .message_len = 200,
    .customization_string = "My Tagged Application",
    .customization_string_len = 21,
    .digest = {0x1c73bed5, 0x73d74e95, 0x59bb4628, 0xe3a8e3db, 0x7ae7830f,
               0x5944ff4b, 0xb4c2f1f2, 0xceb8ebec, 0xc601ba67, 0x57b88a2e,
               0x9b492d8d, 0x6727bbd1, 0x90117868, 0x6a300a02, 0x1d28de97,
               0x5d3030cc},
    .digest_len = 16,
    .digest_len_is_fixed = false,
};


dif_kmac_config_t testConfigs [] = {
  {
    .entropy_mode = kDifKmacEntropyModeEdn,
    .entropy_fast_process = false,
    .entropy_hash_threshold = 50, // TODO:  find a good value here
    .entropy_wait_timer = 0,
    .entropy_prescaler = 1,
    .message_big_endian = false,
    .output_big_endian = false,
    .sideload = false,
    .msg_mask = false,
  },

};

enum {
  kKmacTestConfigsLen = ARRAYSIZE(testConfigs),
};

status_t test_kmac_sw_entropy(void) {
  LOG_INFO("Running KMAC ENTROPY STRESS test...");

  // Initialize KMAC HWIP
  dif_kmac_t kmac;
  CHECK_DIF_OK(
      dif_kmac_init(mmio_region_from_addr(TOP_EARLGREY_KMAC_BASE_ADDR), &kmac));

  // Main test loop
  for (size_t i = 0; i < kKmacTestConfigsLen; i++) {
    // Encode customization string
    dif_kmac_customization_string_t encoded_cust_str;
    CHECK_DIF_OK(dif_kmac_customization_string_init(
        kKmacTestVector.customization_string,
        kKmacTestVector.customization_string_len, &encoded_cust_str));

    // Configure KMAC
    CHECK_DIF_OK(dif_kmac_configure(&kmac, testConfigs[i]));

    // Begin KMAC operation
    dif_kmac_operation_state_t kmac_operation_state;
    CHECK_DIF_OK(dif_kmac_mode_kmac_start(
        &kmac, &kmac_operation_state, kKmacTestVector.mode, kKmacTestVector.digest_len,
        &kKmacTestVector.key, &encoded_cust_str));

    CHECK_DIF_OK(dif_kmac_absorb(&kmac, &kmac_operation_state,
                                 kKmacTestVector.message,
                                 kKmacTestVector.message_len, NULL));


    CHECK(kKmacDigestLenMax >= kKmacTestVector.digest_len);
    uint32_t out[kKmacDigestLenMax];
    CHECK_DIF_OK(dif_kmac_squeeze(&kmac, &kmac_operation_state, out,
                                        kKmacTestVector.digest_len,
                                        /*processed=*/NULL, /*capacity=*/NULL));
  }


  return OK_STATUS();
}

bool test_main(void) {
  static status_t result;

  EXECUTE_TEST(result, test_kmac_entropy);

  return status_ok(result);
}
