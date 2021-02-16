set(APP_SRCS ./App/App.cpp)
set(APP_INC_DIRS "${APP_INC_DIRS} ./App/")
set(ENCLAVE_SRCS ./Enclave/Enclave1.cpp)
set(EDL ./Enclave/Enclave1.edl)

get_filename_component(EDL_NAME ${EDL} NAME_WE)
get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
set(EDL_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.c")
set(SEARCH_PATHS ".")
set(ENCLAVE2_INC_DIRS   "${ENCLAVE_INC_DIRS} ./Enclave2/")
set(ENCLAVE_INC_DIRS   "${ENCLAVE_INC_DIRS} ./Enclave/")

####Build enclave1_t.c/.h
add_custom_command(OUTPUT ${EDL_T_C}
        COMMAND ${SGX_EDGER8R} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
        MAIN_DEPENDENCY ${EDL_ABSPATH}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
add_library(enclave1-edlobj OBJECT ${EDL_T_C})
set_target_properties(enclave1-edlobj PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
target_include_directories(enclave1-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.h")

####Build enclave1.so
add_library(enclave1 SHARED $<TARGET_OBJECTS:enclave1-edlobj> ${ENCLAVE_SRCS})
set_target_properties(enclave1 PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
target_include_directories(enclave1 PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})
target_link_libraries(enclave1 "${SGX_COMMON_CFLAGS} \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
            -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            -Wl,--defsym,__ImageBase=0")
target_include_directories(enclave1 PRIVATE Enclave/)
add_dependencies(enclave1 enclave1-edlobj)

####Sign the enclave1
if(SGX_HW AND SGX_MODE STREQUAL "Release")
    add_custom_target(enclave1-sign ALL
            COMMAND ${SGX_ENCLAVE_SIGNER} gendata
            -config Enclave/Enclave.config.xml
            -enclave enclave1.so -out enclave1_hash.hex ${IGN_INIT} ${IGN_REL}
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
            --cyan "SGX production enclave first step signing finished, \
    use ${CMAKE_CURRENT_BINARY_DIR}/enclave_hash.hex for second step"
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
else()
    add_custom_target(enclave1-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${CMAKE_CURRENT_SOURCE_DIR}/Enclave/Enclave_private.pem
            -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave/Enclave.config.xml
            -enclave libenclave1.so
            -out enclave1.signed.so
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
add_dependencies(enclave1-sign enclave1)
set(CLEAN_FILES "enclave1.signed.so;enclave1_hash.hex")
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")

######################################### Second Enclave ##############################################

set(ENCLAVE2_SRCS ./Enclave2/Enclave2.cpp)
set(EDL2 ./Enclave2/Enclave2.edl)


get_filename_component(EDL2_NAME ${EDL2} NAME_WE)
get_filename_component(EDL2_ABSPATH ${EDL2} ABSOLUTE)
set(EDL2_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL2_NAME}_t.c")

####Build enclave2_t.c/.h
add_custom_command(OUTPUT ${EDL2_T_C}
        COMMAND ${SGX_EDGER8R} --trusted ${EDL2_ABSPATH} --search-path ${SEARCH_PATHS}
        MAIN_DEPENDENCY ${EDL2_ABSPATH}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
add_library(enclave2-edlobj OBJECT ${EDL2_T_C})
set_target_properties(enclave2-edlobj PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
target_include_directories(enclave2-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE2_INC_DIRS})
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL2_NAME}_t.h")

####Build enclave2.so
add_library(enclave2 SHARED $<TARGET_OBJECTS:enclave2-edlobj> ${ENCLAVE2_SRCS})
set_target_properties(enclave2 PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
target_include_directories(enclave2 PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE2_INC_DIRS})
target_link_libraries(enclave2 "${SGX_COMMON_CFLAGS} \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
            -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            -Wl,--defsym,__ImageBase=0")
target_include_directories(enclave2 PRIVATE ${ENCLAVE2_INC_DIRS})
add_dependencies(enclave2 enclave2-edlobj)

####Sign the enclave
if(SGX_HW AND SGX_MODE STREQUAL "Release")
    add_custom_target(enclave2-sign ALL
            COMMAND ${SGX_ENCLAVE_SIGNER} gendata
            -config Enclave2/Enclave.config.xml
            -enclave enclave2.so -out enclave2_hash.hex ${IGN_INIT} ${IGN_REL}
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
            --cyan "SGX production enclave first step signing finished, \
    use ${CMAKE_CURRENT_BINARY_DIR}/enclave_hash.hex for second step"
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
else()
    add_custom_target(enclave2-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${CMAKE_CURRENT_SOURCE_DIR}/Enclave2/Enclave_private.pem
            -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave2/Enclave.config.xml
            -enclave libenclave2.so
            -out enclave2.signed.so
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()
add_dependencies(enclave2-sign enclave2)
set(CLEAN_FILES "enclave2.signed.so;enclave2_hash.hex")
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")


####Build App
set(EDL_U_C "Enclave1_u.c")

add_custom_command(OUTPUT ${EDL_U_C}
        COMMAND ${SGX_EDGER8R} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
        MAIN_DEPENDENCY ${EDL_ABSPATH}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(EDL2_U_C "Enclave2_u.c")

add_custom_command(OUTPUT ${EDL2_U_C}
        COMMAND ${SGX_EDGER8R} --untrusted ${EDL2_ABSPATH} --search-path ${SEARCH_PATHS}
        MAIN_DEPENDENCY ${EDL2_ABSPATH}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(multiEnclaves ${APP_SRCS} ${EDL_U_C} ${EDL2_U_C})
set_target_properties(multiEnclaves PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})
target_include_directories(multiEnclaves PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INC_DIRS})
target_link_libraries(multiEnclaves "${SGX_COMMON_CFLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_USVC_LIB} \
                                         -lsgx_ukey_exchange \
                                         -lpthread")
add_dependencies(multiEnclaves enclave1-sign enclave2-sign)

set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${EDL2_NAME}_u.h")
