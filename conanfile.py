from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout


class Pktvisor(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeToolchain", "CMakeDeps"

    def requirements(self):
        self.requires("catch2/3.8.0")
        self.requires("corrade/2020.06")
        self.requires("cpp-httplib/0.18.3")
        self.requires("docopt.cpp/0.6.3")
        self.requires("fast-cpp-csv-parser/cci.20240102")
        self.requires("json-schema-validator/2.3.0")
        self.requires("libmaxminddb/1.10.0")
        self.requires("nlohmann_json/3.11.3")
        self.requires("openssl/3.3.2")
        if self.settings.os != "Windows":
            self.requires("libpcap/1.10.5", force=True)
        else:
            self.requires("npcap/1.70")
        self.requires("opentelemetry-cpp/1.17.0")
        self.requires("pcapplusplus/23.09")
        self.requires("protobuf/5.27.0")
        self.requires("sigslot/1.2.2")
        self.requires("fmt/10.2.1", force=True)
        self.requires("spdlog/1.15.0")
        self.requires("uvw/3.4.0")
        self.requires("yaml-cpp/0.8.0")
        self.requires("robin-hood-hashing/3.11.5")
        self.requires("libcurl/8.11.1")
        if (
            "libc" not in self.settings.compiler.fields
            or self.settings.compiler.libc != "musl"
        ):
            self.requires("sentry-crashpad/0.6.5")

    def build_requirements(self):
        self.tool_requires("corrade/2020.06")
        self.tool_requires("protobuf/5.27.0")

    def layout(self):
        cmake_layout(self)
