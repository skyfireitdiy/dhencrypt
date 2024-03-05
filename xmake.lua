add_requires("cryptopp", "thrift")

add_includedirs("include", "gen-cpp")

target("dhencrypt")
set_kind("static")
add_files("src/dhencrypt.cpp", "gen-cpp/*.cpp|Comm_server.skeleton.cpp")
add_packages("cryptopp", "thrift")
target_end()

target("client")
set_kind("binary")
add_files("src/client.cpp")
add_packages("cryptopp", "thrift")
add_deps("dhencrypt")
target_end()

target("server")
set_kind("binary")
add_files("gen-cpp/Comm_server.skeleton.cpp")
add_packages("cryptopp", "thrift")
add_deps("dhencrypt")
target_end()
