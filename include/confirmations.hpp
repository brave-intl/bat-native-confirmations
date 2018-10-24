#pragma once
#include <iostream>
#include <vector>

namespace bat_native_confirmations {

  class Confirmations {
   public:

    const int low_token_threshold = 100;
    const int refill_amount = 5 * low_token_threshold;

    std::string server_confirmations_key;

    std::vector<std::string> original_confirmation_tokens;
    std::vector<std::string> blinded_confirmation_tokens;
    ////////////////////////////////////////
    Confirmations();
    ~Confirmations();
    void test();
    void step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(std::string GHpair);
    void step_2_1_batchGenerateTokensAndBlindThem();

   protected:
   private:
  };

}
