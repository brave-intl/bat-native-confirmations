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

  void Confirmations::step_2_1_maybeBatchGenerateConfirmationTokensAndBlindThem() {

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
      this->original_confirmation_tokens.push_back(token_base64);
      this->blinded_confirmation_tokens.push_back(blinded_token_base64);
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

    if (this->signed_blinded_confirmation_tokens.size() <= 0) {
      std::cout << "ERR: step_3_1a, no signed blinded confirmation tokens" << std::endl;
      return;
    }

    std::string orig_token_b64 = this->original_confirmation_tokens.front();
    std::string sb_token_b64 = this->signed_blinded_confirmation_tokens.front();

    // rehydrate
    Token restored_token = Token::decode_base64(orig_token_b64);
    SignedToken signed_token = SignedToken::decode_base64(sb_token_b64);
    // use blinding scalar to unblind
    UnblindedToken client_unblinded_token = restored_token.unblind(signed_token);
    // dehydrate  
    std::string base64_unblinded_token = client_unblinded_token.encode_base64();
    // put on object
    this->unblinded_signed_confirmation_token = base64_unblinded_token;
    // persist?
    this->saveState();

    std::cout << "step3.1a unblinding signed blinded confirmations" << std::endl;
  }

  void Confirmations::step_3_1b_generatePaymentTokenAndBlindIt() {

    // see also: Confirmations::step_2_1_batchGenerateConfirmationTokensAndBlindThem()

    // client prepares a random token and blinding scalar pair
    Token token = Token::random();
    std::string token_base64 = token.encode_base64();

    // client blinds the token
    BlindedToken blinded_token = token.blind();
    std::string blinded_token_base64 = blinded_token.encode_base64();

    // client stores the original token and the blinded token
    // will send blinded token to server
    this->original_payment_tokens.push_back(token_base64);
    this->blinded_payment_tokens.push_back(blinded_token_base64);
    
    this->saveState();
    std::cout << "step3.1b: generate payment, count: " << original_confirmation_tokens.size() << std::endl;
  }

  void Confirmations::step_3_2_storeConfirmationIdAndWorth(std::string confirmationId, std::string paymentWorth) {

    this->confirmation_id = confirmationId;
    this->payment_worth = paymentWorth;

    this->saveState();
    std::cout << "step3.2: store confirmationId and Worth" << std::endl;
  }

  void Confirmations::step_4_2_storeSignedBlindedPaymentToken(std::string signedBlindedPaymentToken) {

    this->signed_blinded_payment_tokens.push_back(signedBlindedPaymentToken);

    this->saveState();
    std::cout << "step4.2 store signed blinded payment" << std::endl;
  }

  void Confirmations::step_5_1_unblindSignedBlindedPayments() {

    // see also Confirmations::step_3_1a_unblindSignedBlindedConfirmations() {

    int n = this->signed_blinded_payment_tokens.size();

    if (n <= 0) {
      std::cout << "ERR: step_5_1, no signed blinded payment tokens" << std::endl;
      return;
    }

    this->unblinded_signed_payment_tokens.clear();

    for (int i = 0; i < n; i++) {
      std::string orig_token_b64 = this->original_payment_tokens[i];
      std::string sb_token_b64 = this->signed_blinded_payment_tokens[i];

      // rehydrate
      Token restored_token = Token::decode_base64(orig_token_b64);
      SignedToken signed_token = SignedToken::decode_base64(sb_token_b64);
      // use blinding scalar to unblind
      UnblindedToken client_unblinded_token = restored_token.unblind(signed_token);
      // dehydrate  
      std::string base64_unblinded_token = client_unblinded_token.encode_base64();
      // put on object
      this->unblinded_signed_payment_tokens.push_back(base64_unblinded_token);
    }

    // persist?
    this->saveState();

    std::cout << "step5.1 unlind signed blinded payments" << std::endl;
  }

  void Confirmations::step_5_2_storeTransactionIdsAndActualPayment() {

    this->saveState();
    std::cout << "step5.2 store txn ids and actual payment" << std::endl;
  }

  bool Confirmations::verifyBatchDLEQProof(std::string proof_string,
                                           std::vector<std::string> blinded_strings,
                                           std::vector<std::string> signed_strings,
                                           std::string public_key_string) {

    bool failure = 0;
    bool success = 1;

    BatchDLEQProof batch_proof = BatchDLEQProof::decode_base64(proof_string);

    std::vector<BlindedToken> blinded_tokens;
    for (auto x : blinded_strings) {
      blinded_tokens.push_back(BlindedToken::decode_base64(x));
    }

    std::vector<SignedToken> signed_tokens;
    for (auto x : signed_strings) {
      signed_tokens.push_back(SignedToken::decode_base64(x));
    }

    PublicKey public_key = PublicKey::decode_base64(public_key_string);
    
    if (!batch_proof.verify(blinded_tokens, signed_tokens, public_key)) {
      return failure;
    }
  
    return success;
  }

  void Confirmations::saveState() {
    // TODO: serialize
    // TODO: call out to client
    std::cout << "saving state... | ";
  }

  void Confirmations::loadState() {
    // TODO: deserialize
    // TODO: call out to client?
    std::cout << "loading state... | ";
  }

  void Confirmations::popFrontConfirmation() {
    auto &a = this->original_confirmation_tokens;
    auto &b = this->blinded_confirmation_tokens;
    auto &c = this->signed_blinded_confirmation_tokens;

    a.erase(a.begin());
    b.erase(b.begin());
    c.erase(c.begin());
  }

  void Confirmations::popFrontPayment() {
    auto &a = this->original_payment_tokens;
    auto &b = this->blinded_payment_tokens;
    auto &c = this->signed_blinded_payment_tokens;

    a.erase(a.begin());
    b.erase(b.begin());
    c.erase(c.begin());
  }

  void MockServer::test() {
    // std::cout << __PRETTY_FUNCTION__ << std::endl;
  }

  void MockServer::generateSignedBlindedTokensAndProof(std::vector<std::string> blinded_tokens) {

    std::vector<std::string> stamped;

    std::vector<BlindedToken> rehydrated_blinded_tokens;
    std::vector<SignedToken>  rehydrated_signed_tokens;

    for (auto x : blinded_tokens) {
      // rehydrate the token from the base64 string
      BlindedToken blinded_token = BlindedToken::decode_base64(x);
      // keep it for the proof later
      rehydrated_blinded_tokens.push_back(blinded_token);

      // server signs the blinded token 
      SignedToken signed_token = this->signing_key.sign(blinded_token);
      // keep it for the proof later
      rehydrated_signed_tokens.push_back(signed_token);

      std::string base64_signed_token = signed_token.encode_base64();
      // std::cout<<"[SERVER] base64_signed_tok: "<<base64_signed_token<<"\n";
      stamped.push_back(base64_signed_token);
    }

    BatchDLEQProof server_batch_proof = BatchDLEQProof(rehydrated_blinded_tokens, rehydrated_signed_tokens, this->signing_key);;
    std::string base64_batch_proof = server_batch_proof.encode_base64();
    // std::cout<<"[SERVER] base64_batch_proof: "<<base64_batch_proof<<"\n";

    this->signed_tokens = stamped;
    this->batch_dleq_proof = base64_batch_proof;

    return;
  }

}
