set(CMAKE_C_FLAGS "-std=gnu99 -Wall")

find_package(LibPcsclite)

set(EXAMPLES
	change_akey
	deploy_club
	format_picc
	get_applications
	get_files
	get_value
	get_ndef
	test_auth
        change_keysettings
	mfsh
	print_uid)

include_directories(${PCSCLITE_INCLUDEDIR})
foreach(example ${EXAMPLES})
	add_executable(${example} EXCLUDE_FROM_ALL ${example}.c pcsc_common.c)
	target_link_libraries(${example} ${PCSCLITE_LIBRARIES} mf)
endforeach(example)

target_link_libraries(mfsh edit)

add_custom_target(examples DEPENDS ${EXAMPLES})
