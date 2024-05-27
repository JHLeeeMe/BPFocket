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

foreach(SOURCE_FILE ${SRC_G})
    get_filename_component(SOURCE_NAME ${SOURCE_FILE} NAME_WE)

    # Create Target
    add_executable(${SOURCE_NAME}
        ${SOURCE_FILE}
        ${HDR_G}
    )

    # Set target postfix
    set_target_properties(${SOURCE_NAME}
        PROPERTIES
            DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX}
            RELWITHDEBINFO_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX}
    )

    # -I
    target_include_directories(${SOURCE_NAME}
        PUBLIC
            ${CMAKE_SOURCE_DIR}/include
    )
endforeach()
