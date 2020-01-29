cmake_minimum_required(VERSION 3.10)
project(tun2socks)

add_subdirectory(3rd_party/argparse)
add_subdirectory(3rd_party/catch2)
add_subdirectory(3rd_party/fmt)
option(SPDLOG_FMT_EXTERNAL "Use external fmt library instead of bundled" ON)
add_subdirectory(3rd_party/spdlog)


set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)
set(LWIP_INCLUDE_DIRS "${LWIP_DIR}/src/include")
add_subdirectory(lwip)

set(CMAKE_CXX_STANDARD 14)

set(SOCKS5_SRC
        socks5/socks5.h
        socks5/socks5_auth.h
        socks5/socks5_client.cpp
        socks5/socks5_client.h)

set(Error_SRC
        error/error_code.h)

set(TunTap_SRC
        tuntap/tap-windows.h
        tuntap/tuntap.cpp
        tuntap/tuntap.h)

set(Pool_SRC
        pool/pool.hpp)

set(Connector_SRC
        connector/connector.h
        connector/connector.cpp)

set(Core_SRC
        core/core.cpp
        core/core.h
        core/config.h)

set(Wrapper_SRC
        wrapper/lwip.hpp
        wrapper/pbuf.hpp)

set(Allocator_SRC
        allocator/allocator.hpp)

set(TUN2SOCKS_SRC
        ${SOCKS5_SRC}
        ${TunTap_SRC}
        ${Error_SRC}
        ${Pool_SRC}
        ${Connector_SRC}
        ${Core_SRC}
        ${Wrapper_SRC}
        ${Allocator_SRC}
        main.cpp)

add_executable(tun2socks ${TUN2SOCKS_SRC})

if (UNIX)
    target_compile_definitions(tun2socks PUBLIC LINUX)
    target_sources(tun2socks PRIVATE
            tuntap/tuntapimpl_linux.cpp
            tuntap/tuntapimpl_linux.h)
endif (UNIX)

find_package(Boost REQUIRED COMPONENTS system coroutine)

target_include_directories(tun2socks PRIVATE . ${Boost_INCLUDE_DIR} lwip/src/include)
target_link_libraries(tun2socks PRIVATE lwipcore ${Boost_LIBRARIES} argparse fmt::fmt spdlog)
