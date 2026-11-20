cmake_minimum_required(VERSION 3.20)
project(cert-lens LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(cert_parse STATIC src/cert.cpp)
target_include_directories(cert_parse PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(cert_parse PUBLIC crypt32)
target_compile_definitions(cert_parse PRIVATE UNICODE _UNICODE NOMINMAX)
if (MSVC)
  target_compile_options(cert_parse PRIVATE /W4 /permissive- /utf-8)
endif()

add_executable(cert-lens WIN32 src/main.cpp)
target_link_libraries(cert-lens PRIVATE cert_parse user32 gdi32 comdlg32 shell32)
target_compile_definitions(cert-lens PRIVATE UNICODE _UNICODE NOMINMAX)
if (MSVC)
  target_compile_options(cert-lens PRIVATE /W4 /permissive- /utf-8)
endif()

enable_testing()
add_executable(cert_tests tests/test_cert.cpp)
target_link_libraries(cert_tests PRIVATE cert_parse)
target_compile_definitions(cert_tests PRIVATE
  UNICODE _UNICODE NOMINMAX
  SAMPLE_PEM_PATH="${CMAKE_SOURCE_DIR}/samples/example.pem"
  SAMPLE_CER_PATH="${CMAKE_SOURCE_DIR}/samples/example.cer"
  GARBAGE_PATH="${CMAKE_SOURCE_DIR}/tests/garbage.bin")
if (MSVC)
  target_compile_options(cert_tests PRIVATE /W4 /permissive- /utf-8)
endif()
add_test(NAME cert_tests COMMAND cert_tests)
