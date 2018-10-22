#include <iostream>
//#include "../deps/challenge-bypass-ristretto-ffi/src/wrapper.hpp"
#include "wrapper.hpp"

using namespace challenge_bypass_ristretto;

int main() {

  SigningKey sKey = SigningKey::random();

  std::cout << "make all works: " << sKey.encode_base64() << std::endl;

  return 0;
}
