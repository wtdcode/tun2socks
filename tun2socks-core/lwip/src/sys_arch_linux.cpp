#include "lwip/sys.h"
#include "boost/date_time.hpp"
#include <memory>

static std::unique_ptr<boost::posix_time::ptime> sys_start_time;

void sys_init(void) {
    sys_start_time = std::make_unique<boost::posix_time::ptime>(boost::posix_time::microsec_clock::local_time());
}

static long long
sys_get_ms_longlong(void){
    if(sys_start_time == nullptr)
        sys_init();
    return (boost::posix_time::microsec_clock::local_time() - *sys_start_time).total_microseconds();
}

u32_t
sys_jiffies(void){
    return (u32_t)sys_get_ms_longlong();
}

u32_t
sys_now(void){
    return (u32_t)sys_get_ms_longlong();
}
