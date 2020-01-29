#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <argparse.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "core/config.h"
#include "core/core.h"
#include "fmt/core.h"
#include "socks5/socks5_auth.h"

int main(int argc, char** argv) {
    argparse::ArgumentParser program("tun2socks");
    program.add_argument("-tip", "--tunIP")
        .help("The IP address of the TUN interface.")
        .default_value(std::string("10.1.2.1"));
    program.add_argument("-tmask", "--tunMask")
        .help("The mask of the TUN interface.")
        .default_value(std::string("255.255.255.128"));
    program.add_argument("-sip", "--socks5IP")
        .help("The IP address of your socks5 server.")
        .default_value(std::string("127.0.0.1"));
    program.add_argument("-sport", "--socks5Port")
        .help("The port of your socks5 server.")
        .default_value(1080)
        .action([](const std::string& port) { return std::stoi(port); });
    program.add_argument("-u", "--username")
        .help("SOCKS5 username. Leave it blank if no authentication.");
    program.add_argument("-p", "--password")
        .help("SOCKS5 password. Leave it blank if no authentication.");
    program.add_argument("-l", "--level")
        .help(
            "Set logging level. 0(Off), 1(Error), 2(Critical), 3(Warning), "
            "4(Info), 5(Debug), 6(Trace).")
        .default_value(4)
        .action([](const std::string& port) { return std::stoi(port); });
    program.add_argument("-f", "--log-file")
        .help("The path to log file. Logs are printed by default.");

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return -1;
    }
    std::shared_ptr<spdlog::logger> logger;
    if (!program.present("-f"))
        logger = spdlog::stdout_color_mt("tun2socks");
    else
        logger = spdlog::basic_logger_mt("tun2socks", program.get("-f"));
    spdlog::set_default_logger(logger);
    auto levelNum = program.get<int>("-l");
    spdlog::level::level_enum level;
    switch (levelNum) {
        case 0:
            level = spdlog::level::off;
            break;
        case 1:
            level = spdlog::level::err;
            break;
        case 2:
            level = spdlog::level::critical;
            break;
        case 3:
            level = spdlog::level::warn;
            break;
        case 4:
            level = spdlog::level::info;
            break;
        case 5:
            level = spdlog::level::debug;
            break;
        case 6:
            level = spdlog::level::trace;
            break;
        default:
            level = spdlog::level::info;
    }
    spdlog::set_level(level);
    spdlog::flush_on(spdlog::level::info);
    int socks5port = program.get<int>("-sport");
    if (socks5port > 65535 || socks5port <= 0) {
        fmt::print("Invalid port number: {}\n", socks5port);
        return -1;
    }
    boost::asio::ip::address_v4 tunip;
    boost::asio::ip::address_v4 tunmask;
    boost::asio::ip::address_v4 socks5ip;
    try {
        tunip = boost::asio::ip::make_address_v4(program.get("-tip"));
        tunmask = boost::asio::ip::make_address_v4(program.get("-tmask"));
        socks5ip = boost::asio::ip::make_address_v4(program.get("-sip"));
    } catch (const boost::system::system_error& err) {
        fmt::print("{}\n", err.what());
    }
    std::shared_ptr<toys::socks5::AuthMethod> method;
    if (program.present("-u") && program.present("-p")) {
        std::string username = program.get("-u");
        std::string password = program.get("-p");
        method = std::make_shared<toys::socks5::UsernamePasswordAuth>(username,
                                                                      password);
    } else {
        method = std::make_shared<toys::socks5::NoAuth>();
    }
    toys::core::TUN2SOCKSConfig config{
        boost::asio::ip::make_network_v4(tunip, tunmask),
        boost::asio::ip::tcp::endpoint(socks5ip,
                                       (unsigned short int)socks5port),
        method};
    spdlog::info("Config: {}", config.to_string());
    auto core = std::make_unique<toys::core::Core>(std::move(config));
    return core->Run();
}