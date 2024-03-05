add_requires("cryptopp")

add_includedirs("include")

target("dhencrypt")
set_kind("static")
add_files("src/dhencrypt.cpp")
add_packages("cryptopp")
target_end()

target("client")
set_kind("binary")
add_files("src/client.cpp")
add_packages("cryptopp")
add_deps("dhencrypt")
target_end()

target("server")
set_kind("binary")
add_files("src/server.cpp")
add_packages("cryptopp")
add_deps("dhencrypt")
target_end()
