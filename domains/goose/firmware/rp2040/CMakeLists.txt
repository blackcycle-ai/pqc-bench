cmake_minimum_required(VERSION 3.13)
include(pico_sdk_import.cmake)
project(pqc_bench_rp2040 C CXX ASM)
set(CMAKE_C_STANDARD 11)
pico_sdk_init()

# PQClean sources (vendored under pqm4). Override with -DPQCLEAN=/path for a non-default layout.
set(PQCLEAN "${CMAKE_CURRENT_SOURCE_DIR}/../../../../repo/pqm4/mupq/pqclean" CACHE PATH "path to PQClean sources")

# pick scheme at configure time:  cmake -DSCHEME=falcon ..   (default: mldsa44)
set(SCHEME "mldsa44" CACHE STRING "scheme: mldsa44 | falcon | mlkem")
if(SCHEME STREQUAL "falcon")
    set(SCHEME_DIR ${PQCLEAN}/crypto_sign/falcon-512/clean)
    set(SCHEME_DEF SCHEME_FALCON)
    set(NITERS 3)      # Falcon clean (FP emulation) on M0+ is brutally slow
elseif(SCHEME STREQUAL "mlkem")
    set(SCHEME_DIR ${PQCLEAN}/crypto_kem/ml-kem-512/clean)
    set(SCHEME_DEF SCHEME_MLKEM)
    set(NITERS 50)     # ML-KEM is light on M0+ (unlike Falcon)
else()
    set(SCHEME_DIR ${PQCLEAN}/crypto_sign/ml-dsa-44/clean)
    set(SCHEME_DEF SCHEME_MLDSA)
    set(NITERS 50)
endif()
file(GLOB SCHEME_SRC ${SCHEME_DIR}/*.c)

add_executable(pqc_bench main.c ${SCHEME_SRC} ${PQCLEAN}/common/fips202.c)
target_compile_definitions(pqc_bench PRIVATE ${SCHEME_DEF} N_ITERS=${NITERS})
target_include_directories(pqc_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/shim ${SCHEME_DIR} ${PQCLEAN}/common)
target_link_libraries(pqc_bench pico_stdlib)

# output over USB CDC (not UART), and emit the .uf2 to drag onto the Pico
pico_enable_stdio_usb(pqc_bench 1)
pico_enable_stdio_uart(pqc_bench 0)
pico_add_extra_outputs(pqc_bench)
