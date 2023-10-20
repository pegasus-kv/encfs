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

#include "encfs.h"

#include <gtest/gtest.h>
#include <openssl/aes.h>

#include <algorithm>

#include "fuzz/util.h"
#include "port/likely.h"
#include "rocksdb/utilities/options_type.h"
#include "test_util/testharness.h"
#include "test_util/testutil.h"

namespace ROCKSDB_NAMESPACE {

// Make sure the length of KEY is larger than the max KeySize(EncryptionMethod).
const unsigned char KEY[33] =
    "\xe4\x3e\x8e\xca\x2a\x83\xe1\x88\xfb\xd8\x02\xdc\xf3\x62\x65\x3e"
    "\x00\xee\x31\x39\xe7\xfd\x1d\x92\x20\xb1\x62\xae\xb2\xaf\x0f\x1a";

// Make sure the length of IV_RANDOM, IV_OVERFLOW_LOW and IV_OVERFLOW_FULL is
// larger than the max BlockSize(EncryptionMethod).
const unsigned char IV_RANDOM[17] =
    "\x77\x9b\x82\x72\x26\xb5\x76\x50\xf7\x05\xd2\xd6\xb8\xaa\xa9\x2c";
const unsigned char IV_OVERFLOW_LOW[17] =
    "\x77\x9b\x82\x72\x26\xb5\x76\x50\xff\xff\xff\xff\xff\xff\xff\xff";
const unsigned char IV_OVERFLOW_FULL[17] =
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

// Get the encryption method from string, case-insensitive.
EncryptionMethod EncryptionMethodStringToEnum(std::string name) {
  std::transform(name.begin(), name.end(), name.begin(), ::toupper);
  EncryptionMethod method;
  if (!ParseEnum<EncryptionMethod>(encryption_method_enum_map, name, &method)) {
    return EncryptionMethod::kUnknown;
  }
  return method;
}

// Get the encryption method string from EncryptionMethod.
std::string EnumToEncryptionMethodString(EncryptionMethod method) {
  std::string name;
  if (!SerializeEnum<EncryptionMethod>(encryption_method_enum_map, method,
                                       &name)) {
    return "";
  }
  return name;
}

TEST(EncryptionTest, KeySize) {
  ASSERT_EQ(16, KeySize(EncryptionMethod::kAES128_CTR));
  ASSERT_EQ(24, KeySize(EncryptionMethod::kAES192_CTR));
  ASSERT_EQ(32, KeySize(EncryptionMethod::kAES256_CTR));
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
  ASSERT_EQ(16, KeySize(EncryptionMethod::kSM4_CTR));
#endif
  ASSERT_EQ(0, KeySize(EncryptionMethod::kUnknown));
}

TEST(EncryptionTest, BlockSize) {
  ASSERT_EQ(16, BlockSize(EncryptionMethod::kAES128_CTR));
  ASSERT_EQ(16, BlockSize(EncryptionMethod::kAES192_CTR));
  ASSERT_EQ(16, BlockSize(EncryptionMethod::kAES256_CTR));
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
  ASSERT_EQ(16, BlockSize(EncryptionMethod::kSM4_CTR));
#endif
  ASSERT_EQ(0, BlockSize(EncryptionMethod::kUnknown));
}

TEST(EncryptionTest, EncryptionMethodStringToEnum) {
  ASSERT_EQ(EncryptionMethod::kAES128_CTR,
            EncryptionMethodStringToEnum("AES128CTR"));
  ASSERT_EQ(EncryptionMethod::kAES192_CTR,
            EncryptionMethodStringToEnum("AES192CTR"));
  ASSERT_EQ(EncryptionMethod::kAES256_CTR,
            EncryptionMethodStringToEnum("AES256CTR"));
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
  ASSERT_EQ(EncryptionMethod::kSM4_CTR, EncryptionMethodStringToEnum("SM4CTR"));
#endif
  ASSERT_EQ(EncryptionMethod::kAES128_CTR,
            EncryptionMethodStringToEnum("aes128ctr"));
  ASSERT_EQ(EncryptionMethod::kAES128_CTR,
            EncryptionMethodStringToEnum("AES128ctr"));
  ASSERT_EQ(EncryptionMethod::kUnknown, EncryptionMethodStringToEnum("xxx"));
}

TEST(EncryptionTest, EnumToEncryptionMethodString) {
  ASSERT_EQ("AES128CTR",
            EnumToEncryptionMethodString(EncryptionMethod::kAES128_CTR));
  ASSERT_EQ("AES192CTR",
            EnumToEncryptionMethodString(EncryptionMethod::kAES192_CTR));
  ASSERT_EQ("AES256CTR",
            EnumToEncryptionMethodString(EncryptionMethod::kAES256_CTR));
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
  ASSERT_EQ("SM4CTR", EnumToEncryptionMethodString(EncryptionMethod::kSM4_CTR));
#endif
  ASSERT_EQ("", EnumToEncryptionMethodString(EncryptionMethod::kUnknown));
}

TEST(EncryptionTest, CreateFromUriFailed) {
  // A valid uri example:
  // "provider={id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF;method=AES128CTR};"
  std::map<std::string, std::vector<std::string>> providers_by_messages(
      {{"NotFound: Missing configurable object: provider",
        {"", "provider=;", "provider={};", "provider={id=};",
         "provider={id=AESx};"}},
       {"Invalid argument: 'hex_instance_key' is not set",
        {"provider={id=AES;hex_instance_key=};",
         "provider={id=AES;hex_instance_key=;};"}},
       {"Invalid argument: 'method' is not set",
        {"provider={id=AES};",  // 'method' is checked firstly.
         "provider={id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF};",
         "provider={id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF;"
         "method=};",
         "provider={id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF;"
         "method=;};"}},
       {"Invalid argument: 'hex_instance_key' is not a hexadecimal string in "
        "even number",
        {"provider={id=AES;hex_instance_key=0;method=AES128CTR};",
         "provider={id=AES;hex_instance_key=GG;method=AES128CTR};"}},
       {"Invalid argument: No mapping for enum : method",
        {"provider={id=AES;hex_instance_key=" + std::string(32, '0') +
             ";method=AES129CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(32, '0') +
             ";method=AES128CTR1};",
         "provider={id=AES;hex_instance_key=" + std::string(32, '0') +
             ";method=AES128CT};",
         "provider={id=AES;hex_instance_key=" + std::string(32, '0') +
             ";method=AES128ECB};"}},
       {"Invalid argument: 'hex_instance_key' length is not valid",
        // Valid hexadecimal string length is either 32, 48 or 64.
        // The match rule of 'hex_instance_key' and 'method' is checked in
        //  EncryptionTest.CreateFromUriSuccessButFailedAtRuntime.
        {"provider={id=AES;hex_instance_key=" + std::string(30, '0') +
             ";method=AES128CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(34, '0') +
             ";method=AES128CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(46, '0') +
             ";method=AES192CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(50, '0') +
             ";method=AES192CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(62, '0') +
             ";method=AES256CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(66, '0') +
             ";method=AES256CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(30, '0') +
             ";method=SM4CTR};",
         "provider={id=AES;hex_instance_key=" + std::string(34, '0') +
             ";method=SM4CTR};"}}});

  const ConfigOptions config_options;
  Env* raw_env = nullptr;
  std::shared_ptr<Env> env_guard;
  for (const auto& providers_by_message : providers_by_messages) {
    for (const auto& provider : providers_by_message.second) {
      std::string fs_uri = provider + "id=EncryptedFileSystem";
      // Env::CreateFromUri fails with expected error.
      Status s =
          Env::CreateFromUri(config_options, "", fs_uri, &raw_env, &env_guard);
      ASSERT_EQ(providers_by_message.first, s.ToString());
      ASSERT_EQ(Env::Default(), raw_env);
      ASSERT_EQ(nullptr, env_guard.get());
    }
  }
}

// Test that although the Env can be created, but it will fail when do file read
// or write operations.
TEST(EncryptionTest, CreateFromUriSuccessButFailedAtRuntime) {
  // Prepare 'invalid_key_size_by_methods' for tests.
  std::map<EncryptionMethod, std::set<size_t>> invalid_key_size_by_methods;
  std::map<EncryptionMethod, size_t> key_size_by_method({
    {EncryptionMethod::kAES128_CTR, KeySize(EncryptionMethod::kAES128_CTR)},
        {EncryptionMethod::kAES192_CTR, KeySize(EncryptionMethod::kAES192_CTR)},
        {EncryptionMethod::kAES256_CTR, KeySize(EncryptionMethod::kAES256_CTR)},
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
    {
      EncryptionMethod::kSM4_CTR, KeySize(EncryptionMethod::kSM4_CTR)
    }
#endif
  });
  for (const auto& left : key_size_by_method) {
    std::set<size_t> invalid_key_sizes;
    for (const auto& right : key_size_by_method) {
      if (left.second != right.second) {
        invalid_key_sizes.insert(right.second);
      }
    }
    invalid_key_size_by_methods[left.first] = invalid_key_sizes;
  }

  // Prepare a test file.
  std::string test_file = "CreateFromUriSuccessButFailedAtRuntime.txt";
  ASSERT_OK(WriteStringToFile(Env::Default(), Slice("test"), test_file, true));

  const ConfigOptions config_options;
  Env* raw_env = nullptr;
  std::shared_ptr<Env> env_guard;
  for (const auto& invalid_key_size_by_method : invalid_key_size_by_methods) {
    EncryptionMethod method = invalid_key_size_by_method.first;
    for (const auto& invalid_key_size : invalid_key_size_by_method.second) {
      // The Env can be created successfully.
      std::string fs_uri = "provider={id=AES;hex_instance_key=" +
                           std::string(2 * invalid_key_size, '0') +
                           ";method=" + EnumToEncryptionMethodString(method) +
                           "};id=EncryptedFileSystem";
      ASSERT_OK(
          Env::CreateFromUri(config_options, "", fs_uri, &raw_env, &env_guard));
      ASSERT_NE(Env::Default(), raw_env);
      ASSERT_EQ(env_guard.get(), raw_env);

      // Write file fail with expected error.
      std::unique_ptr<WritableFile> wf;
      Status s = raw_env->ReopenWritableFile(test_file, &wf, EnvOptions());
      ASSERT_TRUE(s.IsInvalidArgument()) << s.ToString();
      ASSERT_EQ(
          "Invalid argument: 'hex_instance_key' length and 'method' are "
          "not matched",
          s.ToString());

      // Read file fail with expected error.
      std::unique_ptr<SequentialFile> rf;
      s = raw_env->NewSequentialFile(test_file, &rf, EnvOptions());
      ASSERT_TRUE(s.IsInvalidArgument()) << s.ToString();
      ASSERT_EQ(
          "Invalid argument: 'hex_instance_key' length and 'method' are "
          "not matched",
          s.ToString());
    }
  }
}

TEST(EncryptionTest, CreateFromUriSuccess) {
  const std::vector<std::string> uris(
      {"{id=AES;hex_instance_key=" + std::string(32, '0') +
           ";method=AES128CTR}",
       "{id=AES;hex_instance_key=" + std::string(48, '0') +
           ";method=AES192CTR}",
       "{id=AES;hex_instance_key=" + std::string(64, '0') +
           ";method=AES256CTR}",
       "{id=AES;hex_instance_key=" + std::string(32, '0') + ";method=SM4CTR}"});

  std::string test_file = "CreateFromUriSuccess.txt";
  const ConfigOptions config_options;
  Env* raw_env = nullptr;
  std::shared_ptr<Env> env_guard;
  for (const auto& uri : uris) {
    // The Env can be created successfully.
    std::string fs_uri = "provider=" + uri + "; id=EncryptedFileSystem";
    ASSERT_OK(
        Env::CreateFromUri(config_options, "", fs_uri, &raw_env, &env_guard));
    ASSERT_NE(Env::Default(), raw_env);
    ASSERT_EQ(raw_env, env_guard.get());
    ASSERT_TRUE(raw_env->GetFileSystem()->IsInstanceOf(
        EncryptedFileSystem::kClassName()));

    // Write file successfully.
    ASSERT_OK(WriteStringToFile(raw_env, Slice("test"), test_file, true));

    // Read file successfully.
    std::string data;
    ASSERT_OK(ReadFileToString(raw_env, test_file, &data));
    ASSERT_EQ("test", data);
  }
}

// Test to make sure output of AESCTRCipherStream is the same as output from
// OpenSSL EVP API.
class AESCTRCipherStreamTest
    : public testing::TestWithParam<
          std::tuple<AESCTRCipherStream::EncryptType, EncryptionMethod>> {
 public:
  size_t kMaxSize;
  std::unique_ptr<unsigned char[]> plaintext;
  std::unique_ptr<unsigned char[]> ciphertext;
  const unsigned char* current_iv = nullptr;

  AESCTRCipherStreamTest() : kMaxSize(10 * BlockSize(std::get<1>(GetParam()))) {
    CHECK_OK(ReGenerateCiphertext(IV_RANDOM));
  }

  Status ReGenerateCiphertext(const unsigned char* iv) {
    current_iv = iv;

    Random rnd(test::RandomSeed());
    std::string random_string =
        rnd.HumanReadableString(static_cast<int>(kMaxSize));
    plaintext.reset(new unsigned char[kMaxSize]);
    memcpy(plaintext.get(), random_string.data(), kMaxSize);

    evp_ctx_unique_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    CHECK_TRUE(ctx);

    EncryptionMethod method = std::get<1>(GetParam());
    const EVP_CIPHER* cipher = GetEVPCipher(method);
    CHECK_TRUE(cipher != nullptr);

    OPENSSL_RET_NOT_OK(EVP_EncryptInit(ctx.get(), cipher, KEY, current_iv),
                       "EVP_EncryptInit failed.");
    int output_size = 0;
    ciphertext.reset(new unsigned char[kMaxSize]);
    OPENSSL_RET_NOT_OK(
        EVP_EncryptUpdate(ctx.get(), ciphertext.get(), &output_size,
                          plaintext.get(), static_cast<int>(kMaxSize)),
        "EVP_EncryptUpdate failed.");
    int final_output_size = 0;
    OPENSSL_RET_NOT_OK(
        EVP_EncryptFinal(ctx.get(), ciphertext.get() + output_size,
                         &final_output_size),
        "EVP_EncryptFinal failed.");
    CHECK_EQ(kMaxSize, static_cast<size_t>(output_size + final_output_size));
    return Status::OK();
  }

  void TestEncryption(size_t start, size_t end) {
    ASSERT_LT(start, end);
    ASSERT_LE(end, kMaxSize);

    EncryptionMethod method = std::get<1>(GetParam());
    std::string key_str(reinterpret_cast<const char*>(KEY), KeySize(method));
    std::string iv_str(reinterpret_cast<const char*>(current_iv),
                       BlockSize(method));
    std::unique_ptr<AESCTRCipherStream> cipher_stream;
    ASSERT_OK(NewAESCTRCipherStream(method, key_str, iv_str, &cipher_stream));
    ASSERT_TRUE(cipher_stream);

    size_t data_size = end - start;
    // Allocate exact size. AESCTRCipherStream should make sure there will be
    // no memory corruption.
    std::unique_ptr<char[]> data(new char[data_size]);

    if (std::get<0>(GetParam()) == AESCTRCipherStream::EncryptType::kEncrypt) {
      memcpy(data.get(), plaintext.get() + start, data_size);
      ASSERT_OK(cipher_stream->Encrypt(start, data.get(), data_size));
      ASSERT_EQ(0, memcmp(ciphertext.get() + start, data.get(), data_size));
    } else {
      ASSERT_EQ(AESCTRCipherStream::EncryptType::kDecrypt,
                std::get<0>(GetParam()));
      memcpy(data.get(), ciphertext.get() + start, data_size);
      ASSERT_OK(cipher_stream->Decrypt(start, data.get(), data_size));
      ASSERT_EQ(0, memcmp(plaintext.get() + start, data.get(), data_size));
    }
  }
};

TEST_P(AESCTRCipherStreamTest, AESCTRCipherStreamTest) {
  const size_t kBlockSize = BlockSize(std::get<1>(GetParam()));
  // TODO(yingchun): The following tests are based on the fact that the
  //  kBlockSize is 16, make sure they work if adding new encryption methods.
  ASSERT_EQ(kBlockSize, 16);

  // One full block.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(0, kBlockSize));
  // One block in the middle.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5, kBlockSize * 6));
  // Multiple aligned blocks.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5, kBlockSize * 8));

  // Random byte at the beginning of a block.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5, kBlockSize * 5 + 1));
  // Random byte in the middle of a block.
  ASSERT_NO_FATAL_FAILURE(
      TestEncryption(kBlockSize * 5 + 4, kBlockSize * 5 + 5));
  // Random byte at the end of a block.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5 + 15, kBlockSize * 6));

  // Partial block aligned at the beginning.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5, kBlockSize * 5 + 15));
  // Partial block aligned at the end.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5 + 1, kBlockSize * 6));
  // Multiple blocks with a partial block at the end.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5, kBlockSize * 8 + 15));
  // Multiple blocks with a partial block at the beginning.
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize * 5 + 1, kBlockSize * 8));
  // Partial block at both ends.
  ASSERT_NO_FATAL_FAILURE(
      TestEncryption(kBlockSize * 5 + 1, kBlockSize * 8 + 15));

  // Lower bits of IV overflow.
  ASSERT_OK(ReGenerateCiphertext(IV_OVERFLOW_LOW));
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize, kBlockSize * 2));
  // Full IV overflow.
  ASSERT_OK(ReGenerateCiphertext(IV_OVERFLOW_FULL));
  ASSERT_NO_FATAL_FAILURE(TestEncryption(kBlockSize, kBlockSize * 2));
}

class AESEncryptionProviderTestBase {
 public:
  explicit AESEncryptionProviderTestBase(EncryptionMethod method)
      : method_(method) {
    std::string hex_instance_key(2 * KeySize(method_), 'A');
    std::string uri = "id=AES;hex_instance_key=" + hex_instance_key +
                      ";method=" + EnumToEncryptionMethodString(method_);
    Status s =
        EncryptionProvider::CreateFromString(ConfigOptions(), uri, &provider_);
    assert(s.ok());
  }

 protected:
  const EncryptionMethod method_;
  std::shared_ptr<EncryptionProvider> provider_;
};

class AESEncryptionProviderTest
    : public AESEncryptionProviderTestBase,
      public testing::TestWithParam<EncryptionMethod> {
 public:
  AESEncryptionProviderTest() : AESEncryptionProviderTestBase(GetParam()) {}
};

TEST_P(AESEncryptionProviderTest, CreateFromString) {
  // Test EncryptionProvider::CreateFromString.
  std::string value =
      "id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF;"
      "method=AES128CTR;";
  std::shared_ptr<EncryptionProvider> provider;
  ASSERT_OK(
      EncryptionProvider::CreateFromString(ConfigOptions(), value, &provider));
  ASSERT_NE(nullptr, provider.get());

  // Test FileSystem::CreateFromString.
  std::string base_opts = std::string("provider={" + value + "}; id=") +
                          EncryptedFileSystem::kClassName();
  std::shared_ptr<FileSystem> fs;
  ASSERT_OK(FileSystem::CreateFromString(ConfigOptions(), base_opts, &fs));
  ASSERT_NE(nullptr, fs.get());
}

TEST_P(AESEncryptionProviderTest, EncryptAndDecryptFileKey) {
  // Generate a file key.
  size_t key_size = KeySize(method_);
  char file_key[key_size];
  memset(file_key, 'a', key_size);
  char origin_file_key[key_size];
  memcpy(origin_file_key, file_key, key_size);
  char encrypted_file_key[key_size];

  // Loop 10 times to ensure it's repeatable.
  auto provider = dynamic_cast<AESEncryptionProvider*>(provider_.get());
  for (int i = 0; i < 10; i++) {
    // Encrypt the file key.
    ASSERT_OK(provider->EncryptFileKey(file_key, key_size));
    ASSERT_NE(Slice(origin_file_key, key_size), Slice(file_key, key_size));
    if (i == 0) {
      // Initialize 'encrypted_file_key' once.
      memcpy(encrypted_file_key, file_key, key_size);
    }

    // Decrypt the file key.
    ASSERT_OK(provider->DecryptFileKey(file_key, key_size));
    // The 'file_key' matches the 'origin_file_key' after being encrypted and
    // decrypted.
    ASSERT_EQ(Slice(origin_file_key, key_size), Slice(file_key, key_size));
  }
}

TEST_P(AESEncryptionProviderTest, WriteAndReadEncryptionHeader) {
  // Generate an encrypted file header.
  auto provider = dynamic_cast<AESEncryptionProvider*>(provider_.get());
  char header_buf[provider_->GetPrefixLength()];
  ASSERT_OK(provider->WriteEncryptionHeader(header_buf));

  // Read the encrypted file header to 'file_info'.
  AESEncryptionProvider::FileEncryptionInfo file_info;
  ASSERT_OK(provider->ReadEncryptionHeader(
      Slice(header_buf, provider_->GetPrefixLength()), &file_info));

  // Check the content of 'file_info'.
  ASSERT_EQ(method_, file_info.method);
  // Because the file key is random each time generate it, so just check the
  // length.
  ASSERT_EQ(KeySize(method_) * 2, Slice(file_info.key).ToString(true).size());
  ASSERT_EQ(std::string(AES_BLOCK_SIZE, '0'), file_info.iv);
}

class AESEncryptionProviderDeterministicTest
    : public AESEncryptionProviderTestBase,
      public testing::Test,
      public testing::WithParamInterface<
          std::tuple<EncryptionMethod, std::string, std::string>> {
 public:
  AESEncryptionProviderDeterministicTest()
      : AESEncryptionProviderTestBase(std::get<0>(GetParam())) {}
};

TEST_P(AESEncryptionProviderDeterministicTest, EncryptFileKey) {
  // Generate a definite decrypted file key.
  size_t key_size = KeySize(method_);
  char file_key[key_size];
  memset(file_key, 'a', key_size);

  // Encrypt the file key.
  auto provider = dynamic_cast<AESEncryptionProvider*>(provider_.get());
  ASSERT_OK(provider->EncryptFileKey(file_key, key_size));
  // Check the encrypted key is as expect.
  ASSERT_EQ(std::get<1>(GetParam()), Slice(file_key, key_size).ToString(true));
}

TEST_P(AESEncryptionProviderDeterministicTest, DecryptFileKey) {
  // Generate a definite encrypted file key.
  Slice encrypted_hex_file_key(
      "B0F3C75291027257ED912B7075359D7E8767E0C95E847077BCFD55C0C2D64DBA");
  std::string result;
  ASSERT_TRUE(encrypted_hex_file_key.DecodeHex(&result));
  size_t key_size = KeySize(method_);
  char file_key[key_size];
  memcpy(file_key, result.data(), key_size);

  // Decrypt the file key.
  auto provider = dynamic_cast<AESEncryptionProvider*>(provider_.get());
  ASSERT_OK(provider->DecryptFileKey(file_key, key_size));
  // Check the decrypted key is as expect.
  ASSERT_EQ(std::get<2>(GetParam()), Slice(file_key, key_size).ToString(true));
}

INSTANTIATE_TEST_CASE_P(
    , AESCTRCipherStreamTest,
    testing::Combine(testing::Values(AESCTRCipherStream::EncryptType::kEncrypt,
                                     AESCTRCipherStream::EncryptType::kDecrypt),
                     testing::ValuesIn(std::vector<EncryptionMethod> {
                       EncryptionMethod::kAES128_CTR,
                           EncryptionMethod::kAES192_CTR,
                           EncryptionMethod::kAES256_CTR,
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
                           EncryptionMethod::kSM4_CTR
#endif
                     })));

INSTANTIATE_TEST_CASE_P(, AESEncryptionProviderTest,
                        testing::ValuesIn(std::vector<EncryptionMethod> {
                          EncryptionMethod::kAES128_CTR,
                              EncryptionMethod::kAES192_CTR,
                              EncryptionMethod::kAES256_CTR,
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
                              EncryptionMethod::kSM4_CTR
#endif
                        }));
INSTANTIATE_TEST_CASE_P(
    , AESEncryptionProviderDeterministicTest,
    testing::ValuesIn(
        std::vector<std::tuple<EncryptionMethod, std::string, std::string>> {
          std::make_tuple(EncryptionMethod::kAES128_CTR,
                          "DB8AA779C43D547E44AFBE56DE1192F1",
                          "0A18014A345E4748C85FF447CA456EEE"),
              std::make_tuple(
                  EncryptionMethod::kAES192_CTR,
                  "73B8BEBB55C3A262A73DA94D0C6CE8380327B95748A99ED1",
                  "A22A1888A5A0B1542BCDE35C18381427E52138FF774C8FC7"),
              std::make_tuple(EncryptionMethod::kAES256_CTR,
                              "B52961D8E0A5873976991C9F26D3488CC86C664F1CCF85B9"
                              "63F8C42832A4B15D",
                              "64BBC7EB10C6940FFA69568E3287B4932E6AE7E7232A94AF"
                              "BE64F08991139D86"),
#if OPENSSL_VERSION_NUMBER > 0x1010100fL && !defined(OPENSSL_NO_SM4)
              std::make_tuple(EncryptionMethod::kSM4_CTR,
                              "93DA4FEE20004D7019652D9CAC9814F9",
                              "4248E9DDD0635E469595678DB8CCE8E6")
#endif
        }));
}  // namespace ROCKSDB_NAMESPACE

int main(int argc, char** argv) {
  ROCKSDB_NAMESPACE::port::InstallStackTraceHandler();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
