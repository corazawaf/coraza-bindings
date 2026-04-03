cmake_minimum_required(VERSION 3.17)
project(coraza_python C)

find_package(SWIG 4.0 REQUIRED)
# scikit-build-core uses Python3; fall back to Python for standalone CMake usage.
if(NOT Python3_FOUND)
    find_package(Python3 REQUIRED COMPONENTS Development.Module)
endif()
include(UseSWIG)

# LIBCORAZA_ROOT must be set (from scripts/fetch-libcoraza.sh)
if(NOT DEFINED ENV{LIBCORAZA_ROOT} AND NOT DEFINED LIBCORAZA_ROOT)
    message(FATAL_ERROR
        "LIBCORAZA_ROOT is not set. Run scripts/fetch-libcoraza.sh first, "
        "then: LIBCORAZA_ROOT=/path/to/libcoraza pip install -e .")
endif()
if(NOT DEFINED LIBCORAZA_ROOT)
    set(LIBCORAZA_ROOT "$ENV{LIBCORAZA_ROOT}")
endif()

set(LIBCORAZA_A "${LIBCORAZA_ROOT}/libcoraza.a")
if(NOT EXISTS "${LIBCORAZA_A}")
    message(FATAL_ERROR "libcoraza.a not found at ${LIBCORAZA_A}")
endif()

# coraza.i ships with libcoraza starting from v1.3.0.
set(CORAZA_I "${LIBCORAZA_ROOT}/coraza.i")
if(NOT EXISTS "${CORAZA_I}")
    message(FATAL_ERROR "coraza.i not found at ${CORAZA_I}")
endif()

# Copy the interface file into the build tree so UseSWIG can find it.
configure_file("${CORAZA_I}" "${CMAKE_CURRENT_BINARY_DIR}/coraza.i" COPYONLY)

set_source_files_properties(
    "${CMAKE_CURRENT_BINARY_DIR}/coraza.i"
    PROPERTIES CPLUSPLUS OFF
)

swig_add_library(coraza
    TYPE MODULE
    LANGUAGE python
    SOURCES "${CMAKE_CURRENT_BINARY_DIR}/coraza.i"
)

target_include_directories(coraza PRIVATE
    "${LIBCORAZA_ROOT}"
    "${Python3_INCLUDE_DIRS}"
)

target_link_libraries(coraza PRIVATE Python3::Module)

if(APPLE)
    target_link_options(coraza PRIVATE
        -undefined dynamic_lookup
        -Wl,-force_load,${LIBCORAZA_A}
    )
    target_link_libraries(coraza PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
        "-lresolv"
    )
else()
    # Linux
    target_link_options(coraza PRIVATE
        -Wl,--whole-archive ${LIBCORAZA_A} -Wl,--no-whole-archive
    )
    target_link_libraries(coraza PRIVATE pthread dl)
endif()

# Install the native extension alongside the Python package.
# With target "coraza", CMake/SWIG produces _coraza.cpython-*.so (single underscore).
install(TARGETS coraza DESTINATION coraza)

# Install the SWIG-generated coraza.py as _coraza_swig.py
# UseSWIG places generated files in ${CMAKE_CURRENT_BINARY_DIR}
install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/coraza.py"
    DESTINATION coraza
    RENAME _coraza_swig.py
)
