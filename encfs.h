// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once
#include <openssl/evp.h>

#include <string>

#include "rocksdb/env_encryption.h"

namespace ROCKSDB_NAMESPACE {
class AESCTRCipherStream;

using evp_ctx_unique_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

// The encryption method supported.
enum class EncryptionMethod : int {
  kUnknown = 0,
  kAES128_CTR = 1,
  kAES192_CTR = 2,
  kAES256_CTR = 3,
  // OpenSSL support SM4 after 1.1.1 release version.
  kSM4_CTR = 4,
};

static const std::unordered_map<std::string, EncryptionMethod>
    encryption_method_enum_map = {{"", EncryptionMethod::kUnknown},
                                  {"AES128CTR", EncryptionMethod::kAES128_CTR},
                                  {"AES192CTR", EncryptionMethod::kAES192_CTR},
                                  {"AES256CTR", EncryptionMethod::kAES256_CTR},
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
                                  {"SM4CTR", EncryptionMethod::kSM4_CTR}
#endif
};

// Get the key size of the encryption method.
size_t KeySize(EncryptionMethod method);

// Get the block size of the encryption method.
size_t BlockSize(EncryptionMethod method);

// Get the OpenSSL EVP_CIPHER according to the encryption method.
const EVP_CIPHER* GetEVPCipher(EncryptionMethod method);

// Get the last OpenSSL error message.
std::string GetOpenSSLErrors();

// Convert an OpenSSL error to an IOError Status.
#define OPENSSL_RET_NOT_OK(call, msg)                  \
  if (UNLIKELY((call) <= 0)) {                         \
    return Status::IOError((msg), GetOpenSSLErrors()); \
  }

Status NewAESCTRCipherStream(EncryptionMethod method,
                             const std::string& file_key,
                             const std::string& file_key_iv,
                             std::unique_ptr<AESCTRCipherStream>* result);

// The cipher stream for AES-CTR encryption.
class AESCTRCipherStream : public BlockAccessCipherStream {
 public:
  AESCTRCipherStream(const EncryptionMethod method, std::string file_key,
                     uint64_t iv_high, uint64_t iv_low)
      : method_(method),
        file_key_(std::move(file_key)),
        initial_iv_high_(iv_high),
        initial_iv_low_(iv_low) {}

  ~AESCTRCipherStream() override = default;

  size_t BlockSize() override;

  enum class EncryptType : int { kDecrypt = 0, kEncrypt = 1 };

  Status Encrypt(uint64_t file_offset, char* data, size_t data_size) override {
    return Cipher(file_offset, data, data_size, EncryptType::kEncrypt);
  }

  Status Decrypt(uint64_t file_offset, char* data, size_t data_size) override {
    return Cipher(file_offset, data, data_size, EncryptType::kDecrypt);
  }

 protected:
  // Following methods required by BlockAccessCipherStream is unused.

  void AllocateScratch(std::string& /*scratch*/) override {
    // should not be called.
    assert(false);
  }

  Status EncryptBlock(uint64_t /*block_index*/, char* /*data*/,
                      char* /*scratch*/) override {
    return Status::NotSupported("EncryptBlock should not be called.");
  }

  Status DecryptBlock(uint64_t /*block_index*/, char* /*data*/,
                      char* /*scratch*/) override {
    return Status::NotSupported("DecryptBlock should not be called.");
  }

 private:
  Status Cipher(uint64_t file_offset, char* data, size_t data_size,
                EncryptType encrypt_type);

  const EncryptionMethod method_;
  const std::string file_key_;
  const uint64_t initial_iv_high_;
  const uint64_t initial_iv_low_;
};

struct AESEncryptionOptions {
  std::string instance_key;
  EncryptionMethod method;
  AESEncryptionOptions(std::string k = "",
                       EncryptionMethod m = EncryptionMethod::kUnknown)
      : instance_key(std::move(k)), method(m) {
    assert(instance_key.size() == KeySize(method));
  }
};

// TODO(yingchun): Is it possible to derive from CTREncryptionProvider?
// The encryption provider for AES-CTR encryption.
class AESEncryptionProvider : public EncryptionProvider {
 public:
  AESEncryptionProvider();
  ~AESEncryptionProvider() override = default;

  static const char* kClassName() { return "AES"; }
  const char* Name() const override { return kClassName(); }
  bool IsInstanceOf(const std::string& name) const override;

  size_t GetPrefixLength() const override { return kDefaultPageSize; }

  Status CreateNewPrefix(const std::string& /*fname*/, char* prefix,
                         size_t prefix_length) const override;

  Status AddCipher(const std::string& /*descriptor*/, const char* /*cipher*/,
                   size_t /*len*/, bool /*for_write*/) override {
    return Status::NotSupported();
  }

  Status CreateCipherStream(
      const std::string& fname, const EnvOptions& options, Slice& prefix,
      std::unique_ptr<BlockAccessCipherStream>* result) override;

 private:
  friend class AESEncryptionProviderDeterministicTest_DecryptFileKey_Test;
  friend class AESEncryptionProviderDeterministicTest_EncryptFileKey_Test;
  friend class AESEncryptionProviderTest_EncryptAndDecryptFileKey_Test;
  friend class AESEncryptionProviderTest_WriteAndReadEncryptionHeader_Test;

  struct FileEncryptionInfo {
    EncryptionMethod method = EncryptionMethod::kUnknown;
    std::string key;
    std::string iv;  // TODO(yingchun): not used yet
  };

  Status WriteEncryptionHeader(char* header_buf) const;
  Status ReadEncryptionHeader(Slice prefix,
                              FileEncryptionInfo* file_info) const;

  Status EncryptFileKey(char* file_key, size_t file_key_size) const;
  Status DecryptFileKey(char* file_key, size_t file_key_size) const;

  AESEncryptionOptions aes_options_;
};

}  // namespace ROCKSDB_NAMESPACE
