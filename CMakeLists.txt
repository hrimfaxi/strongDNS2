# 设置最低 CMake 版本
cmake_minimum_required(VERSION 3.16)

set(BASE_C_CFLAGS "-Wall -Wextra \
-Wformat -Wformat=2 -Wconversion -Wimplicit-fallthrough \
-Werror=format-security -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
-D_GLIBCXX_ASSERTIONS")

set(CMAKE_C_FLAGS_DEBUG "$ENV{CFLAGS} -O0 -g -DDEBUG=1 ${BASE_C_CFLAGS}")
set(CMAKE_C_FLAGS_RELEASE "$ENV{CFLAGS} -Os -DNDEBUG=1 ${BASE_C_CFLAGS} -s")

# 项目名称
project(strongDNS2 C)

# 添加源文件
set(SOURCES strongDNS2.c xxhash32-ref.c)
include_directories(${CMAKE_BINARY_DIR})

# 添加可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

include(CheckIncludeFile)
macro(find_include FILE VARIABLE)
  check_include_file(${FILE} ${VARIABLE})
  if(${VARIABLE})
    set(INCLUDES ${INCLUDES} ${FILE})
  endif(${VARIABLE})
endmacro(find_include)

find_include(sys/random.h HAVE_SYS_RANDOM_H)


find_package(PkgConfig REQUIRED)

pkg_check_modules(REQUIRED libnetfilter_queue)
pkg_check_modules(REQUIRED libmnl)
pkg_check_modules(REQUIRED libnfnetlink)

# 链接需要的库
target_link_libraries(${PROJECT_NAME} netfilter_queue mnl nfnetlink)

include(GNUInstallDirs)

set(RUNTIME_DATA_DIR "/usr/share" CACHE PATH "Path to runtime data directory")
set(RUNTIME_DATA_PREFIX "${RUNTIME_DATA_DIR}/${PROJECT_NAME}")

configure_file(
  ${CMAKE_SOURCE_DIR}/config.h.in
  ${CMAKE_BINARY_DIR}/config.h
)

install(TARGETS strongDNS2
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

set(DATA_PREFIX "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}")
install(FILES ipv4.txt ipv6.txt
  DESTINATION ${DATA_PREFIX}
)

install(DIRECTORY mark_sites
  DESTINATION ${DATA_PREFIX}
)

get_filename_component(PARENT_DIR ${CMAKE_INSTALL_PREFIX} DIRECTORY)
install(DIRECTORY openwrt-contrib/etc
  DESTINATION "${PARENT_DIR}"
  USE_SOURCE_PERMISSIONS
)
