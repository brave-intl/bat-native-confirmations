#pragma once
#include <iostream>
#include <vector>

using namespace challenge_bypass_ristretto;

namespace bat_native_confirmations {

  class Confirmations {
   public:
    const int low_token_threshold = 1;
    const int refill_amount = 5 * low_token_threshold;

    std::string server_confirmations_key;

    std::vector<std::string>       original_confirmation_tokens;
    std::vector<std::string>        blinded_confirmation_tokens;
    std::vector<std::string> signed_blinded_confirmation_tokens;

    ////////////////////////////////////////
    void test();
    void step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(std::string GHpair);
    void step_2_1_batchGenerateTokensAndBlindThem();
    void step_2_4_storeTheSignedBlindedConfirmations(std::vector<std::string> server_signed_blinded_confirmations);
    void step_3_1a_unblindSignedBlindedConfirmations();
    void saveState();

    Confirmations();
    ~Confirmations();
   protected:
   private:
  };


  class MockServer {
   public:
    SigningKey signing_key = SigningKey::random();
    std::vector<std::string> generateSignedBlindedConfirmationTokens(std::vector<std::string>);
    void test();
    MockServer() {};
    ~MockServer() {};
  };
}
