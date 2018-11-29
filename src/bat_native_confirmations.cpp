#include <iostream>
#include "wrapper.hpp"
#include "confirmations.hpp"
#include "base/guid.h"

#include "happyhttp.h"

using namespace challenge_bypass_ristretto;
using namespace bat_native_confirmations;

static int count=0;

void OnBegin( const happyhttp::Response* r, void* userdata )
{
    // printf("BEGIN (%d %s)\n", r->getstatus(), r->getreason() );
    count = 0;
}

void OnData( const happyhttp::Response* r, void* userdata, const unsigned char* data, int n )
{
    fwrite( data,1,n, stdout );
    count += n;
}

void OnComplete( const happyhttp::Response* r, void* userdata )
{
    // printf("COMPLETE (%d bytes)\n", count );
}

void test() {
  happyhttp::Connection conn( "ads-serve.bravesoftware.com", 80 );
  conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );

  conn.request( "GET", "/v1/catalog" );

  while( conn.outstanding() )
      conn.pump();

  // we should extract the json key `issuers`, save it versioned using issuersVersion and fabricate a version if we don't have one
  // we should key our version of the confirmations objects like this and have them saved as such
  // (make a new obj for each version, maybe have a bool func that states whether it has confirmations to redeem or not)
  // if a newer version has been seen, then any lower version #'d object can be retired after it's been allowed to redeem everything,
  // ie, you pump it until it returns false when asked if it has in-progress items to redeem
  // so we should control how confirmations objects get created, via constructor or something, and how they're saved
  // maybe we should just punt on all of this for now and require them not to rev the keys yet
}

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

  std::string mock_public_key = mock_server.public_key.encode_base64();
  std::vector<std::string> mock_sbc;
  std::string mock_worth = "mock_pub_key_for_lookup_in_catalog";
  std::vector<std::string> mock_sbp;
  std::string mock_sbp_token;
  std::string mock_confirmation_proof;
  std::string mock_payment_proof;

  bool use_server = true;

  // TODO we should pr. do this as multiple queues, unprocessed vs. processed 
  //      this is sort of dependent on the strategy we use for tagging them from the server...


  // TODO: this will get called by bat-native-ads whenever it downloads the ad catalog w/ keys
  {
    conf_client.mutex.lock();
    conf_client.step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(mock_public_key);
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


    mock_server.generateSignedBlindedTokensAndProof(conf_client.blinded_confirmation_tokens);
    mock_sbc = mock_server.signed_tokens;
    mock_confirmation_proof = mock_server.batch_dleq_proof;

    conf_client.step_2_4_storeTheSignedBlindedConfirmations(mock_sbc);

    bool verified = conf_client.verifyBatchDLEQProof(mock_confirmation_proof, 
                                                     conf_client.blinded_confirmation_tokens,
                                                     conf_client.signed_blinded_confirmation_tokens,
                                                     mock_public_key);
    if (!verified) {
      //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
      std::cerr << "ERROR: Confirmations proof invalid" << std::endl;
    }

    // TODO should we simply unblind signed tokens on receipt instead of waiting?

    conf_client.mutex.unlock();
  }


  // reporting ad viewed
  {
    conf_client.mutex.lock();
    conf_client.step_3_1a_unblindSignedBlindedConfirmations();

    conf_client.step_3_1b_generatePaymentTokenAndBlindIt();

    // TODO step_3_1c POST /.../{confirmationId}/{credential}, which is (t, MAC_(sk)(R))

    std::string confirmation_id = base::GenerateGUID();
    std::string request_body = "";
    std::string credential = "";

    // what's `t`? unblinded_signed_confirmation_token
    std::cerr << "unblinded_signed_confirmation_token: " << (conf_client.unblinded_signed_confirmation_token) << "\n";
    // what's `MAC_{sk}(R)`? item from blinded_payment_tokens
    std::cerr << "blinded_payment_tokens: " << (conf_client.blinded_payment_tokens[0]) << "\n";

    // TODO on success, pop fronts: 
    conf_client.popFrontConfirmation();
    // TODO on inet failure, retry or cleanup & unlock

    // TODO guessing we're going to have to store multiple confirmation_id ?
    conf_client.step_3_2_storeConfirmationIdAndWorth(confirmation_id, mock_worth);
    conf_client.mutex.unlock();
  }


  // retrieve payment IOU
  {
    conf_client.mutex.lock();
    // TODO step_4_1 GET /.../tokens/{paymentId}
    // TODO on inet failure, retry or cleanup & unlock

    mock_server.generateSignedBlindedTokensAndProof(conf_client.blinded_payment_tokens);
    mock_sbp = mock_server.signed_tokens;
    mock_sbp_token = mock_sbp.front();
    mock_payment_proof = mock_server.batch_dleq_proof;

    conf_client.step_4_2_storeSignedBlindedPaymentToken(mock_sbp_token);

    bool verified = conf_client.verifyBatchDLEQProof(mock_payment_proof, 
                                                     conf_client.blinded_payment_tokens,
                                                     conf_client.signed_blinded_payment_tokens,
                                                     mock_public_key);
    if (!verified) {
      //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
      std::cerr << "ERROR: Payment proof invalid" << std::endl;
    }

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


  if (use_server) {
    test();
    // conf_client.test();
  }

  return 0;
}
