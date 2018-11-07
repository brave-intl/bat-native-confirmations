#pragma once
#include <iostream>
#include <vector>

namespace bat_native_confirmations {

  using namespace challenge_bypass_ristretto;

  class Confirmations {
   public:
    std::mutex mutex;

    const size_t low_token_threshold = 20;
    const size_t refill_amount = 5 * low_token_threshold;

    std::string server_confirmations_key;

    std::vector<std::string>       original_confirmation_tokens;
    std::vector<std::string>        blinded_confirmation_tokens;
    std::vector<std::string> signed_blinded_confirmation_tokens;
    std::string             unblinded_signed_confirmation_token;

    std::vector<std::string>            original_payment_tokens;
    std::vector<std::string>             blinded_payment_tokens;
    std::vector<std::string>      signed_blinded_payment_tokens;
    std::vector<std::string>    unblinded_signed_payment_tokens;
    
    std::string confirmation_id;
    std::string payment_worth;

    ////////////////////////////////////////
    void test();
    void step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(std::string GHpair);
    void step_2_1_maybeBatchGenerateConfirmationTokensAndBlindThem();
    void step_2_4_storeTheSignedBlindedConfirmations(std::vector<std::string> server_signed_blinded_confirmations);
    void step_3_1a_unblindSignedBlindedConfirmations();
    void step_3_1b_generatePaymentTokenAndBlindIt();
    void step_3_2_storeConfirmationIdAndWorth(std::string confirmationId, std::string paymentWorth);
    void step_4_2_storeSignedBlindedPaymentToken(std::string signedBlindedPaymentToken);
    void step_5_1_unblindSignedBlindedPayments();
    void step_5_2_storeTransactionIdsAndActualPayment();

    bool verifyBatchDLEQProof(std::string proof_string, 
                              std::vector<std::string> blind_strings,
                              std::vector<std::string> signed_strings,
                              std::string public_key_string);

    void popFrontConfirmation();
    void popFrontPayment();
    void saveState();
    void loadState();

    Confirmations();
    ~Confirmations();
   protected:
   private:
  };


  class MockServer {
   public:
    SigningKey signing_key = SigningKey::random();
    PublicKey public_key = signing_key.public_key();

    std::vector<std::string> signed_tokens;
    std::string batch_dleq_proof;

    void generateSignedBlindedTokensAndProof(std::vector<std::string> blinded_tokens);

    void test();
    MockServer();
    ~MockServer();
  };
}
