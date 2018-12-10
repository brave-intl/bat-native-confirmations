#include <iostream>
#include <string>
#include <regex>
#include <cstdlib>
#include "wrapper.hpp"
#include "confirmations.hpp"
#include "happyhttp.h"

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"

#include "net/base/escape.h"
#include "base/base64.h"
#include "base/guid.h"
#include "base/environment.h"

std::string happy_data; 
int happy_status;
int count;

using namespace challenge_bypass_ristretto;
using namespace bat_native_confirmations;

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

  bool test_with_server = true;
  bool pay_invoices = true; // toggle to test paid/not paid state at step 4.1 200/202

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

  std::string mock_body_22 = "{\"blindedTokens\":[\"lNcLBep59zi5zMWD3s3gT7WpgLPlM7n0YiCD2jdkMlc=\"]}";
  std::string mock_body_sha_256 = "MGyHkaktkuGfmopz+uljkmapS0zLwBB9GJNp68kqVzM=";
  std::string mock_signature_22 = "V+paOGZm0OU36hJCr7BrR49OlMpOiuaGC2DeXXwBWlKU88FXA/MOv5gwl/MqQPHWX5RA1+9YDb/6g6FEcsYnAw==";

  std::string mock_creative_instance_id = "6ca04e53-2741-4d62-acbb-e63336d7ed46";
  // TODO: fill in : hook up into brave-core client / bat-native-ads: populate creative instance id with real one
  std::string real_creative_instance_id = mock_creative_instance_id; // XXX TODO


  std::vector<std::string> real_bat_names = {};
  std::vector<std::string> real_bat_keys = {};

  // TODO: fill in : hook up into brave-core client / bat-native-ads: populate mock_wallet_address with real wallet address
  std::string real_wallet_address = mock_wallet_address; // XXX TODO
  std::string real_wallet_address_secret_key = mock_wallet_address_secret_key; // XXX TODO
  // This is stored on the conf_client as server_confirmation_key server_payment_key
  std::string real_confirmations_public_key = mock_confirmations_public_key;
  std::string real_payments_public_key = mock_payments_public_key;

  if (test_with_server) {
    get_catalog();

    std::unique_ptr<base::Value> value(base::JSONReader::Read(happy_data));
    base::DictionaryValue* dict;
    if (!value->GetAsDictionary(&dict)) {
      std::cerr << "no dict" << "\n";
      abort();
    }

    base::Value *v;
    if (!(v = dict->FindKey("issuers"))) {
      std::cerr << "could not get issuers\n";
      abort();
    }

    base::ListValue list(v->GetList());

    real_bat_names = {};
    real_bat_keys = {};
 
    for (size_t i = 0; i < list.GetSize(); i++) {
      base::Value *x;
      list.Get(i, &x);
      //v.push_back(x->GetString());
      base::DictionaryValue* d;
      if (!x->GetAsDictionary(&d)) {
        std::cerr << "no dict x/d" << "\n";
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

      if (name == "confirmation") {
        real_confirmations_public_key = pubkey; 
      } else if (name == "payment") {
        // per amir, evq, we're not actually using this! so it's not supposed to be appearing in the catalog return but is
        real_payments_public_key = pubkey; 
      } else if (std::regex_match(name, bat_regex) ) {
        real_bat_names.push_back(name);
        real_bat_keys.push_back(pubkey);
      }
    }

    //so now all our mock data is ready to go for step_1 below (it's populated with the return from the server)
  }

  // TODO: hook up into brave-core client / bat-native-ads: this will get called by bat-native-ads when it downloads the ad catalog w/ keys (once only for now?)
  // NOTE: this call can block! it waits on a mutex to unlock. generally all these `step_#_#` calls will
  // step 1
  {
    conf_client.mutex.lock();
    conf_client.step_1_storeTheServersConfirmationsPublicKeyAndGenerator(real_confirmations_public_key,
                                                                         real_payments_public_key,
                                                                         real_bat_names,
                                                                         real_bat_keys);
    conf_client.mutex.unlock();
  }

  // TODO: hook up into brave-core client / bat-native-ads: this should happen on launch (in the background) and on loop/timer (in the background)
  // TODO: hook up into brave-core client / bat-native-ads: we'll need to not show ads whenever we're out of tokens use: conf_client.confirmations_ready_for_ad_showing(); to test
  // step 2
  {
    conf_client.mutex.lock();
    conf_client.step_2_refillConfirmationsIfNecessary(real_wallet_address,
                                                      real_wallet_address_secret_key,
                                                      conf_client.server_confirmation_key);
    conf_client.mutex.unlock();
  }

  { // step 2 mock

    std::string digest = "digest";
    std::string primary = "primary";

    std::vector<uint8_t> mock_dat = conf_client.getSHA256(mock_body_22);
    std::string mock_b64 = conf_client.getBase64(mock_dat);
    DCHECK(mock_b64 == mock_body_sha_256);

    std::vector<uint8_t> mock_skey = conf_client.rawDataBytesVectorFromASCIIHexString(mock_wallet_address_secret_key);

    std::string mock_sha = std::string("SHA-256=").append(mock_body_sha_256);

    std::string mock_signature_field = conf_client.sign(&digest, &mock_sha, 1, primary, mock_skey);
    DCHECK( mock_signature_field.find(mock_signature_22) != std::string::npos);

//          /////////////////////////////////////////////////////////
// 
//          mock_server.generateSignedBlindedTokensAndProof(this->blinded_confirmation_tokens);
//          mock_sbc = mock_server.signed_tokens;
//          mock_confirmation_proof = mock_server.batch_dleq_proof;
// 
//          this->step_2_4_storeTheSignedBlindedConfirmations(mock_sbc);
// 
//          bool mock_verified = this->verifyBatchDLEQProof(mock_confirmation_proof, 
//                                                          this->blinded_confirmation_tokens,
//                                                          this->signed_blinded_confirmation_tokens,
//                                                          mock_confirmations_public_key);
//          if (!mock_verified) {
//            //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
//            std::cerr << "ERROR: Mock confirmations proof invalid" << std::endl;
//          }
//          /////////////////////////////////////////////////////////


  }

  // step 3 - reporting ad viewed
  {
    conf_client.mutex.lock();
    conf_client.step_3_redeemConfirmation(real_creative_instance_id);
    conf_client.mutex.unlock();
  }

  if (pay_invoices) // for testing purposes, mark invoices paid on server
  {  
    // access token can be created using `/auth/token`
    // tokens will expire after an hour

    std::unique_ptr<base::Environment> env(base::Environment::Create());

    std::string key1 = "BRAVE_ADS_SERVE_LOGIN_EMAIL";
    std::string key2 = "BRAVE_ADS_SERVE_LOGIN_PASSWORD";

    std::string result1;
    std::string result2;
    bool has1 = env->GetVar(key1, &result1);
    bool has2 = env->GetVar(key2, &result2);

    if (!has1 || !has2) {
      std::cerr << "Environment keys " << key1 << " or " << key2 << " not set so cannot mark invoices paid" << "\n";
      abort();
    }

    happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
    conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );

    std::string endpoint = std::string("/v1/auth/token");

    const char * h[] = {
      "accept", "application/json",
      "Content-Type", "application/json",
      NULL, NULL };

    std::string real_body = std::string("{\"email\":\"").append(result1).append("\",\"password\":\"").append(result2).append("\"}");

    conn.request("POST", endpoint.c_str(), h, (const unsigned char *)real_body.c_str(), real_body.size());

    while( conn.outstanding() ) conn.pump();
    std::string post_resp = happy_data;

    std::unique_ptr<base::Value> value(base::JSONReader::Read(happy_data));
    base::DictionaryValue* dict;
    if (!value->GetAsDictionary(&dict)) {
      std::cerr << "no pay invoices resp dict" << "\n";
      abort();
    }

    base::Value *v;
    if (!(v = dict->FindKey("accessToken"))) {
      std::cerr << "no pay invoices accessToken\n";
      abort();
    }

    std::string accessToken = v->GetString();

    {
      happyhttp::Connection conn2(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
      conn2.setcallbacks( OnBegin, OnData, OnComplete, 0 );

      std::string endpoint2 = std::string("/v1/invoice/");

      std::string bearer = std::string("Bearer ").append(accessToken);

      const char * h2[] = {
        "Authorization", bearer.c_str(),
        NULL, NULL };

      std::string real_body2 = "";

      conn2.request("POST", endpoint2.c_str(), h2, (const unsigned char *)real_body2.c_str(), real_body2.size());

      while( conn2.outstanding() ) conn2.pump();
      std::string post2_resp = happy_data;
    }
    
  }

  // retrieve payment IOUs
  // step 4
  {
    conf_client.mutex.lock();
    conf_client.step_4_retrievePaymentIOUs();
    conf_client.mutex.unlock();
  }

  // step 4 mock
  {
    // mock_server.generateSignedBlindedTokensAndProof(this->blinded_payment_tokens);
    // mock_sbp = mock_server.signed_tokens;
    // mock_sbp_token = mock_sbp.front();
    // mock_payment_proof = mock_server.batch_dleq_proof;

    // this->step_4_2_storeSignedBlindedPaymentToken(mock_sbp_token);

    // bool mock_verified = this->verifyBatchDLEQProof(mock_payment_proof, 
    //                                                 this->blinded_payment_tokens,
    //                                                 this->signed_blinded_payment_tokens,
    //                                                 mock_payments_public_key);
    // if (!mock_verified) {
    //   //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
    //   std::cerr << "ERROR: Mock payment proof invalid" << std::endl;
    // }
  }

  // cash-in payment IOU
  // we may want to do this in conjunction with the previous retrieval step
  // step 5
  {
    conf_client.mutex.lock();
    conf_client.step_5_cashInPayments(real_wallet_address);
    conf_client.mutex.unlock();
  }

  return 0;
}
