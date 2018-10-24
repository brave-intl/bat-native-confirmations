CC := clang++
CXX_FLAGS := -std=c++17
DEBUG_FLAGS := -O0 -g3 -DDEBUG -Wall
PROD_FLAGS := -Os

RUST_BIN := libchallenge_bypass_ristretto.a
RUST_FFI := deps/challenge-bypass-ristretto-ffi
RUST_SRC := $(RUST_FFI)/src
RUST_DEBUG := $(RUST_FFI)/target/debug/$(RUST_BIN)
RUST_PROD := $(RUST_FFI)/target/release/$(RUST_BIN)

CXX_TEST := cpp.out 
CXX_DEBUG := target/debug/$(CXX_TEST)
CXX_PROD := target/release/$(CXX_TEST)

OS := $(shell uname -s | tr "[:upper:]" "[:lower:]")

ifeq (darwin,$(OS))
	CXX_FLAGS += -framework Security
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

rust-debug: $(RUST_DEBUG) # rust libraries
	cd $(RUST_FFI) && cargo build

rust-release: $(RUST_PROD)
	cd $(RUST_FFI) && cargo build --release

rust-all: rust-debug rust-release

test-out: target/debug/cpp.out

cpp-debug: src/bat_native_confirmations.cpp src/confirmations.cpp # cpp, the main, non-dependency code of this library, bat-native-ads
	$(CC) $(CXX_FLAGS) $(DEBUG_FLAGS) -I./$(RUST_SRC) $(RUST_SRC)/wrapper.cpp $(RUST_DEBUG) -I./include src/*.cpp -o $(CXX_DEBUG)

cpp-release:
	$(CC) $(CXX_FLAGS) $(PROD_FLAGS)  -I./$(RUST_SRC) $(RUST_SRC)/wrapper.cpp $(RUST_PROD)  -I./include src/*.cpp -o $(CXX_PROD)

cpp-all: cpp-debug cpp-release
################################################################################


