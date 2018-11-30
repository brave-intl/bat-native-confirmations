#include <iostream>
#include <string>
#include <regex>
#include "wrapper.hpp"
#include "confirmations.hpp"
#include "base/guid.h"

#include "happyhttp.h"

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"

using namespace challenge_bypass_ristretto;
using namespace bat_native_confirmations;

const char* BRAVE_AD_SERVER = "ads-serve.bravesoftware.com";
int BRAVE_AD_SERVER_PORT = 80;
static int count=0;
static std::string happy_data; 

void OnBegin( const happyhttp::Response* r, void* userdata )
{
    // printf("BEGIN (%d %s)\n", r->getstatus(), r->getreason() );
    count = 0;
    happy_data = "";
}

void OnData( const happyhttp::Response* r, void* userdata, const unsigned char* data, int n )
{
    //fwrite( data,1,n, stdout );
    happy_data.append((char *)data, (size_t)n);
    count += n;
}

void OnComplete( const happyhttp::Response* r, void* userdata )
{
    // printf("COMPLETE (%d bytes)\n", count );
}

void get_catalog() {
  happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
  conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );
  conn.request( "GET", "/v1/catalog" );
  while( conn.outstanding() ) conn.pump();

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

  std::string mock_confirmations_public_key = mock_server.public_key.encode_base64();
  std::string mock_payments_public_key = mock_confirmations_public_key; // hack. mock server only has 1 key for now
  std::vector<std::string> mock_bat_names = {"0.00BAT", "0.01BAT", "0.02BAT"};
  std::vector<std::string> mock_bat_keys  = {mock_payments_public_key, mock_payments_public_key, mock_payments_public_key}; // hack

  std::vector<std::string> mock_sbc;
  std::string mock_worth = "mock_pub_key_for_lookup_in_catalog";
  std::vector<std::string> mock_sbp;
  std::string mock_sbp_token;
  std::string mock_confirmation_proof;
  std::string mock_payment_proof;

  std::string mock_wallet_address = "ed89e4cb-2a66-454a-8276-1d167c2a44fa"; // aka paymentId or payment_id
  std::string mock_wallet_address_secret_key = "56fe77e2a5b2fa3339fe13944856c901cbd926932e0b17257d2f1b03fe15441a2c7420280292d383eed24ba50ca0a3dd03e8fba6871d46f8557b35b6dc367aca";

  bool test_with_server = true;

  if (test_with_server) {
    get_catalog();
    // std::cout << "happy_data: " <<  happy_data << "\n";

    std::unique_ptr<base::Value> value(base::JSONReader::Read(happy_data));
    base::DictionaryValue* dict;
    if (!value->GetAsDictionary(&dict)) {
      std::cout << "no dict" << "\n";
      abort();
    }

    base::Value *v;
    if (!(v = dict->FindKey("issuers"))) {
      std::cout << "could not get issuers\n";
      abort();
    }

    base::ListValue list(v->GetList());

    mock_bat_names = {};
    mock_bat_keys = {};
 
    for (size_t i = 0; i < list.GetSize(); i++) {
      // std::cerr << "i: " << (i) << "\n";
      base::Value *x;
      list.Get(i, &x);
      //v.push_back(x->GetString());
      base::DictionaryValue* d;
      if (!x->GetAsDictionary(&d)) {
        std::cout << "no dict x/d" << "\n";
        abort();
      }
      base::Value *a;
      
      if (!(a = d->FindKey("name"))) {
        std::cerr << "no name\n";
        abort();
      }

      std::string name = a->GetString();

      if (!(a = d->FindKey("publicKey"))) {
        std::cerr << "no pubkey\n";
        abort();
      }

      std::string pubkey = a->GetString();

      std::regex bat_regex("\\d\\.\\d\\dBAT"); // eg, "1.23BAT"

      // std::cerr << "name: " << (name) << " pubkey: " << (pubkey) << "\n";

      if (name == "confirmation") {
        mock_confirmations_public_key = pubkey; 
      } else if (name == "payment") {
        // per amir, evq, we're not actually using this! so it's not supposed to be appearing in the catalog return but is
        mock_payments_public_key = pubkey; 
      } else if (std::regex_match(name, bat_regex) ) {
        mock_bat_names.push_back(name);
        mock_bat_keys.push_back(pubkey);
      }
    }

    //so now all our mock data is ready to go for step_1_1 below (it's populated with the return from the server)
  }

  // TODO: hook up into brave-core client / bat-native-ads: populate mock_wallet_address with real wallet address
  // mock_wallet_address = ... ;

  // TODO: hook up into brave-core client / bat-native-ads: this will get called by bat-native-ads when it downloads the ad catalog w/ keys (once only for now?)
  // NOTE: this call can block! it waits on a mutex to unlock. generally all these `step_#_#` calls will
  {
    conf_client.step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(mock_confirmations_public_key, mock_payments_public_key, mock_bat_names, mock_bat_keys);
  }

  // TODO: hook up into brave-core client / bat-native-ads: this should happen on launch (in the background) and on loop/timer (in the background)
  // TODO: hook up into brave-core client / bat-native-ads: we'll need to not show ads whenever we're out of tokens use: conf_client.confirmations_ready_for_ad_showing(); to test
  {

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    conf_client.mutex.lock();
    conf_client.step_2_1_maybeBatchGenerateConfirmationTokensAndBlindThem();

    // TODO step_2_2 POST the tokens via client
    // TODO          POST: on inet failure, retry or cleanup & unlock
    {
      happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
      conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );

      // /v1/confirmation/token/{payment_id}
      std::string endpoint = std::string("/v1/confirmation/token/").append(mock_wallet_address);

      conn.request("POST", endpoint.c_str());
      while( conn.outstanding() ) conn.pump();

      std::cerr << "POST response: " << (happy_data) << "\n";
    }

    // TODO step_2_3 GET the returned values
    // TODO          GET: on inet failure, retry or cleanup & unlock
    {

    }


    mock_server.generateSignedBlindedTokensAndProof(conf_client.blinded_confirmation_tokens);
    mock_sbc = mock_server.signed_tokens;
    mock_confirmation_proof = mock_server.batch_dleq_proof;

    conf_client.step_2_4_storeTheSignedBlindedConfirmations(mock_sbc);

    bool verified = conf_client.verifyBatchDLEQProof(mock_confirmation_proof, 
                                                     conf_client.blinded_confirmation_tokens,
                                                     conf_client.signed_blinded_confirmation_tokens,
                                                     mock_confirmations_public_key);
    if (!verified) {
      //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
      std::cerr << "ERROR: Confirmations proof invalid" << std::endl;
    }

    // TODO should we simply unblind signed tokens on receipt instead of waiting?
    //      we probably should
    //      we have to now basically because confirmations_ready_for_ad_showing now hinges on this

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
                                                     mock_payments_public_key);
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

  return 0;
}
