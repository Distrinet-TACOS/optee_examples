cmake_minimum_required(VERSION 3.13.0)
project (eratosthenes_communicator C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE host/include)

add_library (mqtt STATIC)
add_library (jsmn INTERFACE)
add_subdirectory(host/lib)

target_link_libraries (${PROJECT_NAME} PRIVATE pthread)
target_link_libraries (${PROJECT_NAME} PRIVATE teec)
target_link_libraries (${PROJECT_NAME} PRIVATE mqtt)
target_link_libraries (${PROJECT_NAME} PRIVATE jsmn)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
