cmake_minimum_required(VERSION 3.10)

project(mbedtls_hashtest C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(crypto)

aux_source_directory(crypto SRC_LIST)

add_library(mbedtls_lib STATIC ${SRC_LIST})

add_executable(rsa_sig main.c)
target_link_libraries(rsa_sig PRIVATE mbedtls_lib)

# ⭐ 修改输出 exe 名字
set_target_properties(rsa_sig PROPERTIES OUTPUT_NAME "signature_RSASSA-PSS")
