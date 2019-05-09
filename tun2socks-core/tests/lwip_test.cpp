#define CATCH_CONFIG_MAIN
#include "catch2/catch.hpp"
#include <lwip/tcp.h>
#include <lwip/netif.h>
#include <lwip/init.h>
#include <lwip/udp.h>
#include <lwip/sys.h>

TEST_CASE("Test basic lwip functions"){
    lwip_init();
    SECTION("Test max udp_pcb"){
        udp_pcb* arr[4096];
        for(int i = 0; i < 4096; i++){
            arr[i] = udp_new();
            REQUIRE(arr[i] != NULL);
        }
    }
}