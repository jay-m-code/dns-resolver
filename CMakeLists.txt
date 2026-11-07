
cmake_minimum_required(VERSION 3.16)

project(dns-resolver-cpp
	VERSION 0.1.0
	LANGUAGES CXX
)

# C++ configuration
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# DNS library
add_library(dns STATIC
	src/dns/Encoder.cpp
)

target_include_directories(dns PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

# CLI executable
add_executable(dnslookup
	src/cli/main.cpp
)

target_link_libraries(dnslookup PRIVATE
	dns
)
