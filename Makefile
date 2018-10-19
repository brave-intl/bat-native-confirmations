CC := clang++
RUST_FFI := deps/challenge-bypass-ristretto-ffi/

all: target rust cpp

target:
	mkdir target

rust: # rust libraries
	cd $(RUST_FFI) && cargo build && cargo build --release

cpp:  # cpp, the main, non-dependency code of this library, bat-native-ads
	$(CC) -std=c++17 -I./include  src/*.cpp -o target/cpp.out

clean:
	cd $(RUST_FFI) && make clean
	rm -rf target


