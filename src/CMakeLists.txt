set(CMAKE_C_FLAGS "-std=c99 -g -Wall")

add_library(mf SHARED error.c app.c auth.c mifare.c crypto.c file.c picc.c util.c)

find_package(LibGcrypt)
target_link_libraries(mf ${GCRYPT_LIBRARIES})

set_target_properties(mf PROPERTIES
	VERSION 0.9
	SOVERSION 0)

install(TARGETS mf
	LIBRARY DESTINATION lib)
