cmake_minimum_required(VERSION 3.10)

project(IoT_Auth_Protocol CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# ---------------------------------------------------------
# 1. 查找并配置依赖包
# ---------------------------------------------------------
find_package(OpenSSL REQUIRED)

find_library(GMP_LIBRARY NAMES gmp)
if(NOT GMP_LIBRARY)
    message(FATAL_ERROR "GMP library not found! Please check your installation.")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${OPENSSL_INCLUDE_DIR})

# ---------------------------------------------------------
# 2. 定义核心源码集合 (避免在多个 Target 中重复编写)
# ---------------------------------------------------------
# 【清理与升级】：彻底移除废弃的 BCHCodec，加入强大的 ReedSolomon 纠错引擎
set(CORE_SOURCES
    src/ReedSolomon.cpp   # 🔥 你的 RS 纠错引擎核心
    src/FuzzyVault.cpp
    src/CryptoModule.cpp
    src/DeterministicECC.cpp
    src/Server.cpp
    src/User.cpp
    src/BioModule.cpp
    src/TEEKeyModule.cpp
    src/SecureRecordLayer.cpp
)

# ---------------------------------------------------------
# 3. 编译真实的 C++ Web 网关服务器 (生产主程序)
# ---------------------------------------------------------
add_executable(iot_gateway_server 
    src/main_server.cpp 
    ${CORE_SOURCES}
)

# Crow 需要 pthread (多线程) 支持，以及 sqlite3 数据库支持
target_link_libraries(iot_gateway_server PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${GMP_LIBRARY} 
    sqlite3 
    pthread
)

# ---------------------------------------------------------
# 4. 编译模糊金库终极压测引擎 (论文理论数据出图)
# ---------------------------------------------------------
add_executable(test_fuzzy_vault 
    test/test_fuzzy_vault.cpp 
    ${CORE_SOURCES}
)

target_link_libraries(test_fuzzy_vault PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${GMP_LIBRARY} 
    sqlite3
)

# ---------------------------------------------------------
# 5. 原生数据集模糊金库批量压测 (FVC Benchmark)
# ---------------------------------------------------------
add_executable(test_batch_vault 
    test/test_batch_vault.cpp 
    ${CORE_SOURCES}
)

target_link_libraries(test_batch_vault PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${GMP_LIBRARY}
    sqlite3
)

# ---------------------------------------------------------
# 6. Method G: 增强版 BioModuleV2 (RS(64,32) t=16) 压测
# ---------------------------------------------------------
add_executable(test_batch_vault_v2
    test/test_batch_vault_v2.cpp
    src/ReedSolomon.cpp
    src/BioModuleV2.cpp
)

target_link_libraries(test_batch_vault_v2 PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${GMP_LIBRARY}
    sqlite3
)