CC := clang++

all: target rust cpp

target:
	mkdir target

rust: # rust libraries
	cd challenge-bypass-ristretto-ffi && cargo build && cargo build --release

cpp:  # cpp, the main, non-dependency code of this library, bat-native-ads
	$(CC) -std=c++17 -I./include  src/*.cpp -o target/cpp.out

clean:
	cd challenge-bypass-ristretto-ffi && make clean
	rm -rf target


