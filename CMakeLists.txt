
cmake_minimum_required(VERSION 3.16)

project(dns-resolver-cpp
	VERSION 0.1.0
	LANGUAGES CXX
)

# C++ configuration
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Testing
enable_testing()

#GTest
include(FetchContent)

FetchContent_Declare(
	googletest
	URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(googletest)

# DNS library
add_library(dns STATIC
	src/dns/Encoder.cpp
	src/dns/QueryBuilder.cpp
	src/dns/Decoder.cpp
)



# Network Library
# Choose correct file
if(WIN32)
    set(NETWORK_SOURCE src/network/UDPTransport_WIN.cpp)
else()
    set(NETWORK_SOURCE src/network/UDPTransport_POSIX.cpp)
endif()

add_library(network STATIC
	${NETWORK_SOURCE}
)

if(WIN32)
	target_link_libraries(network PRIVATE ws2_32)
endif()

# Include
target_include_directories(dns PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(network PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

# CLI executable
add_executable(dnslookup
	src/cli/main.cpp
)

# Executable Libraries
target_link_libraries(dnslookup PRIVATE
	dns
	network
)

# Add Tests

# Name Encoding
add_executable(dnsNameEncoding
	tests/dns_encoding.cpp
	tests/dns_decoding.cpp
)

target_link_libraries(dnsNameEncoding PRIVATE
	dns
	GTest::gtest_main
)

# Query Builder
add_executable(dnsQueryBuilder
	tests/dns_query_builder.cpp
)

target_link_libraries(dnsQueryBuilder PRIVATE
	dns
	GTest::gtest_main
)

# UDP Transport
add_executable(udpTransport
	tests/udp_transport.cpp
)

target_link_libraries(udpTransport PRIVATE
	network
	GTest::gtest_main
)

include(GoogleTest)

gtest_discover_tests(dnsNameEncoding)
gtest_discover_tests(dnsQueryBuilder)
gtest_discover_tests(udpTransport)