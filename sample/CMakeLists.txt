### sample/CMakeLists.txt
###

# Sources
file(GLOB_RECURSE SRC_G
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Headers
file(GLOB_RECURSE HDR_G
    ${CMAKE_SOURCE_DIR}/include/*.h
    ${CMAKE_SOURCE_DIR}/include/*.hpp
)

# Create Target (BPFocket_Sample)
add_executable(BPFocket_Sample
    ${SRC_G}
    ${HDR_G}
)

# Set target postfix
set_target_properties(BPFocket_Sample
    PROPERTIES
        DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX}
        RELWITHDEBINFO_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX}
)

# -I
target_include_directories(BPFocket_Sample
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)
