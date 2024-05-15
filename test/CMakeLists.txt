### test/CMakeLists.txt
###

# Clone GoogleTest
message("FetchContent: googletest")
include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY "https://github.com/google/googletest.git"
  GIT_TAG        "v1.14.0"
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Sources
file(GLOB_RECURSE SRC_G
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Headers
file(GLOB_RECURSE HDR_G
    ${CMAKE_SOURCE_DIR}/include/*.h
    ${CMAKE_SOURCE_DIR}/include/*.hpp
)

# Create Target (BPFocket_Test)
add_executable(BPFocket_Test
    ${SRC_G}
    ${HDR_G}
)

# -I
target_include_directories(BPFocket_Test
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

# -l
target_link_libraries(BPFocket_Test
    PUBLIC 
        gtest
        gtest_main
)
