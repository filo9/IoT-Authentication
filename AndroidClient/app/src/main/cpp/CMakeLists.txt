cmake_minimum_required(VERSION 3.22.1)
project("iotauthclient")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 1. 导入 crypto 静态库
add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/libs/${ANDROID_ABI}/libcrypto.a)

# 2. 导入 ssl 静态库
add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/libs/${ANDROID_ABI}/libssl.a)

# 3. 编译主库
add_library(${CMAKE_PROJECT_NAME} SHARED
        native-lib.cpp
        User.cpp
        BioModule.cpp
        CryptoModule.cpp
        DeterministicECC.cpp
        ReedSolomon.cpp
        TEEKeyModule.cpp
        SecureRecordLayer.cpp
)

# 4. 引入头文件路径 (Modern CMake 方式)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        ssl
        crypto
        dl
        z
        atomic
)

# 1. 隐藏所有 C++ 符号，只暴露 JNI 接口 (JNIEXPORT 会自动突破隐藏)
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
)

# 2. 强行把第三方静态库（OpenSSL）的所有符号吞噬进本地，不对外暴露
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--exclude-libs,ALL")

# 3. 强制优先使用本地符号，不要去系统库里找
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-Bsymbolic")