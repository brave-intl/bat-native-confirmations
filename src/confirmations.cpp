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
    this->saveState();
    std::cout << "step1.1 key: " << this->server_confirmations_key << std::endl;
  }

  void Confirmations::step_2_1_batchGenerateTokensAndBlindThem() {

    if (blinded_confirmation_tokens.size() > low_token_threshold) {
      return;
    }

    while (blinded_confirmation_tokens.size() < refill_amount) {

      // client prepares a random token and blinding scalar pair
      Token token = Token::random();
      std::string token_base64 = token.encode_base64();

      // client blinds the token
      BlindedToken blinded_token = token.blind();
      std::string blinded_token_base64 = blinded_token.encode_base64();

      // client stores the original token and the blinded token
      // will send blinded token to server
      original_confirmation_tokens.push_back(token_base64);
      blinded_confirmation_tokens.push_back(blinded_token_base64);
    }
  
    this->saveState();
    std::cout << "step2.1: batch generate, count: " << original_confirmation_tokens.size() << std::endl;
  }

  void Confirmations::step_2_4_storeTheSignedBlindedConfirmations(std::vector<std::string> server_signed_blinded_confirmations) {
    this->signed_blinded_confirmation_tokens = server_signed_blinded_confirmations;
    this->saveState();
    std::cout << "step2.4: store signed_blinded_confirmations_tokens from server" << std::endl;
  }

  void Confirmations::step_3_1a_unblindSignedBlindedConfirmations() {

    this->saveState();
    std::cout << "step3.1a unblinding signed blinded confirmations" << std::endl;
  }

  void Confirmations::saveState() {
    // TODO: serialize
    // TODO: call out to client
    std::cout << "    saving state..." << std::endl;
  }

  void MockServer::test() {
    // std::cout << __PRETTY_FUNCTION__ << std::endl;
  }

  std::vector<std::string> MockServer::generateSignedBlindedConfirmationTokens(std::vector<std::string> blinded) {

    std::vector<std::string> stamped;

    for (auto x : blinded) {
      // rehydrate the token from the base64 string
      BlindedToken blinded_token = BlindedToken::decode_base64(x);
      // server signs the blinded token 
      SignedToken signed_token = this->signing_key.sign(&blinded_token);
      // and returns the blinded token and dleq proof^H^H^H^H^H^H^H^H^H^H to the client
      std::string base64_signed_token = signed_token.encode_base64();
      // std::cout<<"[SERVER] base64_signed_tok: "<<base64_signed_token<<"\n";
      stamped.push_back(base64_signed_token);
    }

    return stamped;
  }

}
