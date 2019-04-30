cmake_minimum_required(VERSION 3.13)

project(tun2socks-core)

option(STATIC_LIB "Build static lib" ON)

set(coresrc
    "tun2socks-core.cpp"
    "dllmain.cpp"
    "socks5.cpp"
)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)

# The filelist below is from lwIP's cmake files.

# The minimum set of files needed for lwIP.
set(lwipcore_SRCS
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/dns.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/raw.c
    ${LWIP_DIR}/src/core/stats.c
    ${LWIP_DIR}/src/core/sys.c
    ${LWIP_DIR}/src/core/altcp.c
    ${LWIP_DIR}/src/core/altcp_alloc.c
    ${LWIP_DIR}/src/core/altcp_tcp.c
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/tcp_out.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/udp.c
    ${LWIP_DIR}/src/sys_arch.c
)
set(lwipcore4_SRCS
    ${LWIP_DIR}/src/core/ipv4/autoip.c
    ${LWIP_DIR}/src/core/ipv4/dhcp.c
    ${LWIP_DIR}/src/core/ipv4/etharp.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
    ${LWIP_DIR}/src/core/ipv4/igmp.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
)
set(lwipcore6_SRCS
    ${LWIP_DIR}/src/core/ipv6/dhcp6.c
    ${LWIP_DIR}/src/core/ipv6/ethip6.c
    ${LWIP_DIR}/src/core/ipv6/icmp6.c
    ${LWIP_DIR}/src/core/ipv6/inet6.c
    ${LWIP_DIR}/src/core/ipv6/ip6.c
    ${LWIP_DIR}/src/core/ipv6/ip6_addr.c
    ${LWIP_DIR}/src/core/ipv6/ip6_frag.c
    ${LWIP_DIR}/src/core/ipv6/mld6.c
    ${LWIP_DIR}/src/core/ipv6/nd6.c
)

# APIFILES: The files which implement the sequential and socket APIs.
set(lwipapi_SRCS
    ${LWIP_DIR}/src/api/api_lib.c
    ${LWIP_DIR}/src/api/api_msg.c
    ${LWIP_DIR}/src/api/err.c
    ${LWIP_DIR}/src/api/if_api.c
    ${LWIP_DIR}/src/api/netbuf.c
    ${LWIP_DIR}/src/api/netdb.c
    ${LWIP_DIR}/src/api/netifapi.c
    ${LWIP_DIR}/src/api/sockets.c
    ${LWIP_DIR}/src/api/tcpip.c
)

# Files implementing various generic network interface functions
set(lwipnetif_SRCS
    ${LWIP_DIR}/src/netif/ethernet.c
    ${LWIP_DIR}/src/netif/bridgeif.c
    ${LWIP_DIR}/src/netif/bridgeif_fdb.c
    ${LWIP_DIR}/src/netif/slipif.c
)

# 6LoWPAN
set(lwipsixlowpan_SRCS
    ${LWIP_DIR}/src/netif/lowpan6_common.c
    ${LWIP_DIR}/src/netif/lowpan6.c
    ${LWIP_DIR}/src/netif/lowpan6_ble.c
    ${LWIP_DIR}/src/netif/zepif.c
)

# PPP
set(lwipppp_SRCS
    ${LWIP_DIR}/src/netif/ppp/auth.c
    ${LWIP_DIR}/src/netif/ppp/ccp.c
    ${LWIP_DIR}/src/netif/ppp/chap-md5.c
    ${LWIP_DIR}/src/netif/ppp/chap_ms.c
    ${LWIP_DIR}/src/netif/ppp/chap-new.c
    ${LWIP_DIR}/src/netif/ppp/demand.c
    ${LWIP_DIR}/src/netif/ppp/eap.c
    ${LWIP_DIR}/src/netif/ppp/ecp.c
    ${LWIP_DIR}/src/netif/ppp/eui64.c
    ${LWIP_DIR}/src/netif/ppp/fsm.c
    ${LWIP_DIR}/src/netif/ppp/ipcp.c
    ${LWIP_DIR}/src/netif/ppp/ipv6cp.c
    ${LWIP_DIR}/src/netif/ppp/lcp.c
    ${LWIP_DIR}/src/netif/ppp/magic.c
    ${LWIP_DIR}/src/netif/ppp/mppe.c
    ${LWIP_DIR}/src/netif/ppp/multilink.c
    ${LWIP_DIR}/src/netif/ppp/ppp.c
    ${LWIP_DIR}/src/netif/ppp/pppapi.c
    ${LWIP_DIR}/src/netif/ppp/pppcrypt.c
    ${LWIP_DIR}/src/netif/ppp/pppoe.c
    ${LWIP_DIR}/src/netif/ppp/pppol2tp.c
    ${LWIP_DIR}/src/netif/ppp/pppos.c
    ${LWIP_DIR}/src/netif/ppp/upap.c
    ${LWIP_DIR}/src/netif/ppp/utils.c
    ${LWIP_DIR}/src/netif/ppp/vj.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/arc4.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/des.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/md4.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/md5.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/sha1.c
)

# All LWIP files without apps
set(lwipnoapps_SRCS
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipcore6_SRCS}
    ${lwipapi_SRCS}
    ${lwipnetif_SRCS}
    ${lwipsixlowpan_SRCS}
    ${lwipppp_SRCS}
)

# We love C++.
set_source_files_properties(${lwipnoapps_SRCS} PROPERTIES LANGUAGE CXX)

if(STATIC_LIB)
    add_library(${PROJECT_NAME} STATIC ${coresrc} ${lwipnoapps_SRCS})
else(STATIC_LIB)
    add_library(${PROJECT_NAME} SHARED ${coresrc} ${lwipnoapps_SRCS})
endif(STATIC_LIB)

# Don't export lwip include directories.
target_include_directories(${PROJECT_NAME} PRIVATE ${LWIP_DIR}/src/include)

target_include_directories(${PROJECT_NAME} PUBLIC ./include)
add_library(tun2socks::core ALIAS ${PROJECT_NAME})

set_target_properties(${PROJECT_NAME} PROPERTIES
                      CXX_STANDARD 17
                      CXX_EXTENSIONS OFF
                      CXX_STANDARD_REQUIRED ON
)

# see https://github.com/Microsoft/vcpkg/blob/master/ports/boost/usage
#     https://github.com/Microsoft/vcpkg/blob/master/docs/examples/installing-and-using-packages.md#handling-libraries-without-native-cmake-support
find_package(Boost REQUIRED)
target_include_directories(${PROJECT_NAME} PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})

if(WIN32)
    target_sources(${PROJECT_NAME}
                   PRIVATE
                   "tuntap-windows.cpp"
    )
    target_compile_definitions(${PROJECT_NAME}
                               PUBLIC WIN32
                               PUBLIC __WIN32__
                               PUBLIC _WINDOWS
                               PRIVATE _WINSOCK_DEPRECATED_NO_WARNINGS
                               PRIVATE _WIN32_WINNT=0x0A00
                               PRIVATE BOOST_COROUTINES_NO_DEPRECATION_WARNING
                               PRIVATE _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
    )

    if(MSVC)
        # Ignore warning C4103: alignment changed after including header, may be due to missing #pragma pack(pop)
        # /IGNOR:4103 not working here.
        target_compile_options(${PROJECT_NAME} PRIVATE "/wd4103")
        target_link_options(${PROJECT_NAME} PRIVATE "/IGNORE:4221 /IGNORE:4006")
    endif(MSVC)

    target_link_libraries(${PROJECT_NAME} Ws2_32.lib Iphlpapi.lib)
endif(WIN32)