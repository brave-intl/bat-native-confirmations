CC := clang++
CXXFLAGS := -std=c++17
DEBUGFLAGS := -O0 -g3 -DDEBUG -Wall
PRODFLAGS := -Os

RUST_BIN := libchallenge_bypass_ristretto.a
RUST_FFI := deps/challenge-bypass-ristretto-ffi
RUST_SRC := $(RUST_FFI)/src
RUST_DEBUG := $(RUST_FFI)/target/debug/$(RUST_BIN)
RUST_PROD := $(RUST_FFI)/target/release/$(RUST_BIN)

OS := $(shell uname -s | tr "[:upper:]" "[:lower:]")

ifeq (darwin,$(OS))
	CXXFLAGS += -framework Security
endif

all: target debug release

clean:
	cd $(RUST_FFI) && make clean
	rm -rf target

test:
	@./target/debug/cpp.out

.PHONY: all clean test target

################################################################################
debug: target rust-debug cpp-debug

release: target rust-release cpp-release

target:
	@mkdir -p target
	@mkdir -p target/debug
	@mkdir -p target/release

rust-debug: # rust libraries
	cd $(RUST_FFI) && cargo build

rust-release:
	cd $(RUST_FFI) && cargo build --release

rust-all: rust-debug rust-release

cpp-debug:  # cpp, the main, non-dependency code of this library, bat-native-ads
	$(CC) $(CXXFLAGS) $(DEBUGFLAGS) -I./$(RUST_SRC) $(RUST_SRC)/wrapper.cpp $(RUST_DEBUG) -I./include src/*.cpp -o target/debug/cpp.out

cpp-release:
	$(CC) $(CXXFLAGS) $(PRODFLAGS)  -I./$(RUST_SRC) $(RUST_SRC)/wrapper.cpp $(RUST_PROD)  -I./include src/*.cpp -o target/release/cpp.out

cpp-all: cpp-debug cpp-release
################################################################################


