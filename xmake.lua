add_requires("cryptopp")

add_includedirs("include")

target("common")
set_kind("static")
add_files("src/common.cpp")
add_packages("cryptopp")
target_end()

target("client")
set_kind("binary")
add_files("src/client.cpp")
add_packages("cryptopp")
add_deps("common")
target_end()

target("server")
set_kind("binary")
add_files("src/server.cpp")
add_packages("cryptopp")
add_deps("common")
target_end()
