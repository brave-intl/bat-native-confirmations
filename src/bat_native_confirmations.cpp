#include <iostream>
#include "wrapper.hpp"
#include "confirmations.hpp"

using namespace challenge_bypass_ristretto;
using namespace bat_native_confirmations;

int main() {

  //  Client's role, from protocol-flow.png:
  //
  //  Fetching (1)
  //    1.0 (Make a catalog request: bat-native-ads)
  //    1.1 Store "issuers" element (comes back with catalog) (G/H setup)
  //  Whenever low (2)
  //    2.1 batch generate tokens, blind them,
  //    2.2 POST them
  //    Later on:
  //    2.3 GET the signed-blinded-confirmation
  //    2.4 store the signed-blinded-confirmation
  //  Report ad confirmations (3)
  //    3.1a unblind signed-blinded-confirmation,
  //    3.1b generate blinded-payment
  //    3.1c POST /.../{confirmationId}/{credential}, which is (t, MAC_(sk)(R))
  //    3.2 store confirmationId + worth
  //  Redeem Ad confirmation (4)
  //    4.1 GET /.../tokens/{paymentId}
  //    4.2 store returned signed-blinded-payment
  //  Collect Ad payments (5)
  //    5.1 pop signed-blinded-payment, PUT /.../tokens/{paymentId}
  //    5.2 store transactionIds + payment

  bat_native_confirmations::Confirmations conf_client;
  bat_native_confirmations::MockServer mock_server;

  std::string mock_key("mock_key");
  std::vector<std::string> mock_sbc;
  std::string mock_confirmation_id = "mock_conf_id";
  std::string mock_worth = "mock_pub_key_for_lookup_in_catalog";
  std::vector<std::string> mock_sbp;
  std::string mock_sbp_token;

  // TODO we should pr. do this as multiple queues, unprocessed vs. processed 
  //      this is sort of dependent on the strategy we use for tagging them from the server...


  // TODO: this will get called by bat-native-ads whenever it downloads the ad catalog w/ keys
  {
    conf_client.mutex.lock();
    conf_client.step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(mock_key);
    conf_client.mutex.unlock();
  }


  // TODO this should happen on launch and on loop (timer), in the background
  // TODO we'll need to not show ads whenever we're out of tokens
  {
    conf_client.mutex.lock();
    conf_client.step_2_1_maybeBatchGenerateConfirmationTokensAndBlindThem();

    // TODO step_2_2 POST the tokens via client
    // TODO step_2_3 GET the returned values
    // TODO 2x, on inet failure, retry or cleanup & unlock

    mock_sbc = mock_server.generateSignedBlindedTokens(conf_client.blinded_confirmation_tokens);

    // TODO should we simply unblind signed tokens on receipt instead of waiting?
    // TODO DLEQ

    conf_client.step_2_4_storeTheSignedBlindedConfirmations(mock_sbc);
    conf_client.mutex.unlock();
  }


  // reporting ad viewed
  {
    conf_client.mutex.lock();
    conf_client.step_3_1a_unblindSignedBlindedConfirmations();

    conf_client.step_3_1b_generatePaymentTokenAndBlindIt();

    // TODO step_3_1c POST /.../{confirmationId}/{credential}, which is (t, MAC_(sk)(R))
    // TODO on success, pop fronts: 
    conf_client.popFrontConfirmation();
    // TODO on inet failure, retry or cleanup & unlock

    conf_client.step_3_2_storeConfirmationIdAndWorth(mock_confirmation_id, mock_worth);
    conf_client.mutex.unlock();
  }


  // retrieve payment IOU
  {
    conf_client.mutex.lock();
    // TODO step_4_1 GET /.../tokens/{paymentId}
    // TODO on inet failure, retry or cleanup & unlock

    mock_sbp = mock_server.generateSignedBlindedTokens(conf_client.blinded_payment_tokens);
    mock_sbp_token = mock_sbc.front();

    conf_client.step_4_2_storeSignedBlindedPaymentToken(mock_sbp_token);

    // TODO DLEQ
    conf_client.mutex.unlock();
  }


  // cash-in payment IOU
  // we may want to do this in conjunction with the previous retrieval step
  {
    conf_client.mutex.lock();
    conf_client.step_5_1_unblindSignedBlindedPayments();
    // TODO  PUT  (POST?) /.../tokens/{paymentId}
    // TODO on inet failure, retry or cleanup & unlock
    // TODO how long are we keeping these txn ids around? what is format of "actual payment" ? 
    conf_client.step_5_2_storeTransactionIdsAndActualPayment();
    
    // TODO actually, on success we pop payments equal to # retrieved, not just first:
    //conf_client.popFrontPayment();
    conf_client.mutex.unlock();
  }

  return 0;
}
