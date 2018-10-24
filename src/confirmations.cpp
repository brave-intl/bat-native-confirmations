#include <iostream>
#include "wrapper.hpp"
#include "confirmations.hpp"

using namespace challenge_bypass_ristretto;

namespace bat_native_confirmations {

  Confirmations::Confirmations() {
    // std::cout << "Confirmations created\n"; 
  };

  Confirmations::~Confirmations() { 
    // std::cout << "Confirmations destroyed\n"; 
  }

  void Confirmations::test() {
    // std::cout << "Confirmations::test works\n";
  }

  void Confirmations::step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(std::string GHpair) {
    // This (G,H) *pair* is exposed as a *single* string via the rust lib
    // G is the generator the server used in H, see next line
    // H, aka Y, is xG, the server's public key
    // These are both necessary for the DLEQ proof, but not useful elsewhere
    // These come back with the catalog from the server
    // Later we'll get an *array of pairs* for the payments side
    this->server_confirmations_key = GHpair;
    std::cout << "step1.1 key: " << this->server_confirmations_key << std::endl;
  }

  void Confirmations::step_2_1_batchGenerateTokensAndBlindThem() {

    if (blinded_confirmation_tokens.size() > low_token_threshold) {
      return;
    }

    while (blinded_confirmation_tokens.size() < refill_amount) {

      // client prepares a random token and blinding scalar pair
      Token token = Token::random();
      // client stores the original token
      std::string token_base64 = token.encode_base64();

      // client blinds the token
      BlindedToken blinded_token = token.blind();
      // and sends it to the server
      std::string blinded_token_base64 = blinded_token.encode_base64();

      original_confirmation_tokens.push_back(token_base64);
      blinded_confirmation_tokens.push_back(blinded_token_base64);
    }
  
    std::cout << "step2.1: batch generate, count: " << original_confirmation_tokens.size() << std::endl;
  }

}
