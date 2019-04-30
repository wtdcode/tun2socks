cmake_minimum_required(VERSION 3.13)

project(tun2socks-cli)

set(clisrc
    tun2socks-cli.cpp
)

add_executable(${PROJECT_NAME} ${clisrc})

target_link_libraries(${PROJECT_NAME}
                      tun2socks::core
)

set_target_properties(${PROJECT_NAME} PROPERTIES
                      CXX_STANDARD 11
                      CXX_EXTENSIONS OFF
                      CXX_STANDARD_REQUIRED ON
)

if(WIN32)
    target_compile_definitions(${PROJECT_NAME}
                               PRIVATE WIN32
                               PRIVATE __WIN32__
    )
endif(WIN32)