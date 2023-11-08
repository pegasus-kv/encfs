# encfs

The `AESEncryptionProvider` of `EncryptionFileSystem` is an encryption plugin for RocksDB. It depends on OpenSSL to show how an external plugin can bring its dependencies into the RocksDB build. It provides a factory function in a header file to show integration with RocksDB header includes. It can also be enabled in text-based options to demonstrate use of the static registration framework.

## Build
Download the RocksDB code from the official repository. Currently, version 8.5.3 is used as the benchmark for testing.

git clone --depth 1 --branch v8.5.3 https://github.com/facebook/rocksdb.git
The code first needs to be linked under RocksDB's "plugin/" directory. In your RocksDB directory, run:

```
$ pushd ./plugin/
$ git clone https://github.com/pegasus-kv/encfs.git
```

Next, we can build and install RocksDB with this plugin as follows:

```
$ popd
$ make clean && DEBUG_LEVEL=0 ROCKSDB_PLUGINS="encfs" make -j32 db_bench install
```

Build by cmake and check the functionality:
```
#!/usr/bin/env bash

set -ex

# 1. build
mkdir build && cd build
cmake -DWITH_LZ4=1 -DCMAKE_BUILD_TYPE=Debug -DWITH_TESTS=1 -DROCKSDB_BUILD_SHARED=0 -DROCKSDB_PLUGINS=encfs ..
make -j $(nproc)

# 2. run encfs_test
./encfs_test

# 3. Run tests and tools
opts=("id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF;method=AES128CTR"
      "id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;method=AES192CTR"
      "id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;method=AES256CTR"
      "id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF;method=SM4CTR")
for opt in ${opts[*]}; do
  echo "${opt}"

  # 3.1. Run all tests
  # Set env ENCRYPTED_ENV and run all tests
  export ENCRYPTED_ENV=${opt}
  ctest -j $(nproc) -V
  unset ENCRYPTED_ENV

  uri='provider={${uri}};id=EncryptedFileSystem'
  echo "${uri}"

  # 3.2. Run env_basic_test and env_test tests
  # Set env TEST_FS_URI and run env_basic_test and env_test
  export TEST_FS_URI=${uri}
  ./env_basic_test --gtest_filter=*CustomEnv*
  ./env_test --gtest_filter=CreateEnvTest.CreateEncryptedFileSystem
  unset TEST_FS_URI

  # 3.3. Run benchmarks
  ./db_bench --fs_uri="${uri}" --benchmarks="fillseq,readrandom,readseq" --compression_type=lz4 --num=1000000

  # 3.4. Run ldb tools
  ./tools/ldb --fs_uri="${uri}" --db=/tmp/rocksdbtest-1000/dbbench/ put k v
  ./tools/ldb --fs_uri="${uri}" --db=/tmp/rocksdbtest-1000/dbbench/ get k
  ls -l /tmp/rocksdbtest-1000/dbbench | grep "log" | awk '{print $NF}' | xargs -i ./tools/ldb --fs_uri="${uri}" dump_wal --walfile=/tmp/rocksdbtest-1000/dbbench/{} | head
  ./tools/ldb --fs_uri="${uri}" --db=/tmp/rocksdbtest-1000/dbbench/ scan --hex | head
  ./tools/ldb --fs_uri="${uri}" --db=/tmp/rocksdbtest-1000/dbbench/ dump --hex | head
  ./tools/ldb --fs_uri="${uri}" --db=/tmp/rocksdbtest-1000/dbbench/ manifest_dump | head
  ./tools/ldb --fs_uri="${uri}" --db=/tmp/rocksdbtest-1000/dbbench/ list_live_files_metadata | head
done
```

## Tool usage

For RocksDB binaries (such as the `ldb`, `db_bench` we built above), the plugin can be enabled through configuration. `ldb` and `db_bench` in particular takes a `--fs_uri` where we can specify "encfs" , which is the name registered by this plugin. Example usage:

```
$ ./tools/ldb --fs_uri="provider={id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;method=AES256CTR};id=EncryptedFileSystem" --db=/tmp/rocksdbtest-1000/dbbench/ scan --hex | head
$ ./db_bench --benchmarks=fillrandom --fs_uri="provider={id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;method=AES256CTR};id=EncryptedFileSystem" --compression_type=lz4
```

## Application usage

The plugin's interface is also exposed to applications, which can enable it either through configuration or through code. Here is an example instantiating the plugin in code.

```
$ cat <<EOF >./test.cpp
#include <cstdio>
#include <memory>

#include <rocksdb/convenience.h>
#include <rocksdb/env.h>
#include <rocksdb/status.h>

int main() {
  std::string fs_uri = "provider={id=AES;hex_instance_key=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF;method=AES256CTR};id=EncryptedFileSystem";
  rocksdb::Env* raw_env = nullptr;
  std::shared_ptr<rocksdb::Env> env_guard;
  rocksdb::Status s = rocksdb::Env::CreateFromUri(rocksdb::ConfigOptions(), /*env_uri=*/ "", fs_uri, &raw_env, &env_guard);
  if (!s.ok()) {
    fprintf(stderr, "fs_uri='%s'\n", fs_uri.c_str());
    fprintf(stderr, "CreateFromUri() failed with error %s\n", s.ToString().c_str());
    return 1;
  }

  s = rocksdb::WriteStringToFile(raw_env, "test_data", "test.txt", /*should_sync=*/ true);
  if (!s.ok()) {
    fprintf(stderr, "WriteStringToFile() failed with error %s\n", s.ToString().c_str());
    return 1;
  }

  return 0;
}
EOF
$ g++ -std=c++17 -o test test.cpp -lrocksdb -lpthread -llz4 -lcrypto -u encfs_reg
$ ./tmp
```

# Thanks

Some of the implementations are inspired by [Apache Kudu](https://github.com/apache/kudu) and [tikv/rocksdb](https://github.com/tikv/rocksdb)
