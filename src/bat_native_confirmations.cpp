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

  // TODO we should pr. do this as multiple queues, unprocessed vs. processed 
  //      this is sort of dependent on the strategy we use for tagging them from the server...

  // TODO reconcile the fact that we are 'adding' to arrays not 'replacing' them

  conf_client.step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(mock_key);

  // TODO this should pr. happen on a background thread
  conf_client.step_2_1_batchGenerateTokensAndBlindThem();

  //step_2_2 POST the tokens via client
  //step_2_3 GET the returned values

  mock_sbc = mock_server.generateSignedBlindedConfirmationTokens(conf_client.blinded_confirmation_tokens);

  conf_client.step_2_4_storeTheSignedBlindedConfirmations(mock_sbc);
  conf_client.step_3_1a_unblindSignedBlindedConfirmations();

  return 0;
}
