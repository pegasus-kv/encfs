# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

cmake_minimum_required(VERSION 3.10)

find_package(OpenSSL REQUIRED)
set(encfs_LIBS ${OPENSSL_CRYPTO_LIBRARY} PARENT_SCOPE)
set(encfs_INCLUDE_PATHS ${OPENSSL_INCLUDE_DIR} PARENT_SCOPE)

set(encfs_SOURCES "encfs.cc" PARENT_SCOPE)
set(encfs_HEADERS "encfs.h" PARENT_SCOPE)
set(encfs_CMAKE_EXE_LINKER_FLAGS "-u encfs_reg" PARENT_SCOPE)
set(encfs_TESTS "encfs_test.cc" PARENT_SCOPE)
