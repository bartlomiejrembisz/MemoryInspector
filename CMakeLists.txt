cmake_minimum_required(VERSION 3.0.0)
project(MemoryInspector VERSION 0.1.0)

add_executable(MemoryInspector main.cpp)

# Iso image build step
add_custom_command(
	TARGET MemoryInspector POST_BUILD
	COMMAND cp $<TARGET_FILE:MemoryInspector> ${CMAKE_CURRENT_LIST_DIR}/MemoryInspector
)
