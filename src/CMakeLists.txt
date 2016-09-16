find_package ( PkgConfig REQUIRED )

pkg_check_modules ( OPENSSL libcrypto REQUIRED )

include_directories ( ${OPENSSL_INCLUDE_DIRS} )
link_directories ( ${OPENSSL_LINK_DIRS} )

set ( SRC_TOP "${CMAKE_SOURCE_DIR}/src/" )

set ( BN_SOURCES
  ${SRC_TOP}/main.cpp
)

add_executable ( openssl-cipher-test ${BN_SOURCES} )

target_include_directories ( openssl-cipher-test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} )
target_link_libraries ( openssl-cipher-test "-pthread" ${OPENSSL_LIBRARIES} )

install ( TARGETS openssl-cipher-test DESTINATION bin )
