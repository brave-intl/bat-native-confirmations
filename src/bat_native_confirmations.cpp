#include <iostream>
#include <string>
#include <regex>
#include <cstdlib>
#include "wrapper.hpp"
#include "confirmations.hpp"
#include "base/guid.h"
#include "happyhttp.h"

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"

#include "net/base/escape.h"
#include "base/base64.h"

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

  bool test_with_server = true;

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

  // TODO: fill in : hook up into brave-core client / bat-native-ads: populate creative instance id with real one
  std::string mock_creative_instance_id = "6ca04e53-2741-4d62-acbb-e63336d7ed46";
  std::string real_creative_instance_id = mock_creative_instance_id;

  // TODO: fill in : hook up into brave-core client / bat-native-ads: populate mock_wallet_address with real wallet address
  std::string real_wallet_address = mock_wallet_address; // XXX TODO
  std::string real_wallet_address_secret_key = mock_wallet_address_secret_key; // XXX TODO
  // This is stored on the conf_client as server_confirmation_key server_payment_key
  std::string real_confirmations_public_key = mock_confirmations_public_key;
  std::string real_payments_public_key = mock_payments_public_key;

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

      if (name == "confirmation") {
        real_confirmations_public_key = pubkey; 
      } else if (name == "payment") {
        // per amir, evq, we're not actually using this! so it's not supposed to be appearing in the catalog return but is
        real_payments_public_key = pubkey; 
      } else if (std::regex_match(name, bat_regex) ) {
        mock_bat_names.push_back(name);
        mock_bat_keys.push_back(pubkey);
      }
    }

    //so now all our mock data is ready to go for step_1_1 below (it's populated with the return from the server)
  }

  // TODO: hook up into brave-core client / bat-native-ads: this will get called by bat-native-ads when it downloads the ad catalog w/ keys (once only for now?)
  // NOTE: this call can block! it waits on a mutex to unlock. generally all these `step_#_#` calls will
  {
    conf_client.step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(real_confirmations_public_key, real_payments_public_key, mock_bat_names, mock_bat_keys);
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
      std::string digest = "digest";
      std::string primary = "primary";

      /////////////////////////////////////////////////////////////////////////////
      std::vector<uint8_t> mock_dat = conf_client.getSHA256(mock_body_22);
      std::string mock_b64 = conf_client.getBase64(mock_dat);
      DCHECK(mock_b64 == mock_body_sha_256);

      std::vector<uint8_t> mock_skey = conf_client.rawDataBytesVectorFromASCIIHexString(mock_wallet_address_secret_key);

      std::string mock_sha = std::string("SHA-256=").append(mock_body_sha_256);

      std::string mock_signature_field = conf_client.sign(&digest, &mock_sha, 1, primary, mock_skey);
      DCHECK( mock_signature_field.find(mock_signature_22) != std::string::npos);
      /////////////////////////////////////////////////////////////////////////////
      

      /////////////////////////////////////////////////////////////////////////////
      std::string build = "";

      build.append("{\"blindedTokens\":");
      build.append("[");
      std::vector<std::string> a = conf_client.blinded_confirmation_tokens;

      for(size_t i = 0; i < a.size(); i++) {
        if(i > 0) {
          build.append(",");
        }
        build.append("\"");
        build.append(a[i]);
        build.append("\"");
      }

      build.append("]");
      build.append("}");

      std::string real_body = build;

      std::vector<uint8_t> real_sha_raw = conf_client.getSHA256(real_body);
      std::string real_body_sha_256_b64 = conf_client.getBase64(real_sha_raw);

      std::vector<uint8_t> real_skey = conf_client.rawDataBytesVectorFromASCIIHexString(real_wallet_address_secret_key);

      std::string real_digest_field = std::string("SHA-256=").append(real_body_sha_256_b64);

      std::string real_signature_field = conf_client.sign(&digest, &real_digest_field, 1, primary, real_skey);
      /////////////////////////////////////////////////////////////////////////////



      happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
      conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );

      // /v1/confirmation/token/{payment_id}
      std::string endpoint = std::string("/v1/confirmation/token/").append(real_wallet_address);

      const char * h[] = {"digest", (const char *) real_digest_field.c_str(), 
                          "signature", (const char *) real_signature_field.c_str(), 
                          "accept", "application/json",
                          "Content-Type", "application/json",
                          NULL, NULL };

      conn.request("POST", endpoint.c_str(), h, (const unsigned char *)real_body.c_str(), real_body.size());

      while( conn.outstanding() ) conn.pump();

      std::string post_resp = happy_data;

      //TODO this should be the `nonce` in the return. we need to make sure we get the nonce in the separate request  
      //observation. seems like we should move all of this (the tokens in-progress) data to a map keyed on the nonce, and then
      //step the storage through (pump) in a state-wise (dfa) as well, so the storage types are coded (named) on a dfa-state-respecting basis
      
      std::unique_ptr<base::Value> value(base::JSONReader::Read(post_resp));
      base::DictionaryValue* dict;
      if (!value->GetAsDictionary(&dict)) {
        std::cout << "2.2 post resp: no dict" << "\n";
        abort();
      }

      base::Value *v;
      if (!(v = dict->FindKey("nonce"))) {
        std::cout << "2.2 no nonce\n";
        abort();
      }

      conf_client.nonce = v->GetString();

        //STEP 2.3
        // TODO this is done blocking and assumes success but we need to separate it more and account for the possibility of failures
        // TODO GET: on inet failure, retry or cleanup & unlock
        { 
          //conn.request("GET", endpoint.c_str());
          happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
          conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );

          // /v1/confirmation/token/{payment_id}
          std::string endpoint = std::string("/v1/confirmation/token/").append(real_wallet_address).append("?nonce=").append(conf_client.nonce);

          conn.request("GET", endpoint.c_str()  ); // h, (const unsigned char *)real_body.c_str(), real_body.size());

          while( conn.outstanding() ) conn.pump();
          std::string get_resp = happy_data;

          /////////////////////////////////////////////////////////
          mock_server.generateSignedBlindedTokensAndProof(conf_client.blinded_confirmation_tokens);
          mock_sbc = mock_server.signed_tokens;
          mock_confirmation_proof = mock_server.batch_dleq_proof;

          conf_client.step_2_4_storeTheSignedBlindedConfirmations(mock_sbc);

          bool mock_verified = conf_client.verifyBatchDLEQProof(mock_confirmation_proof, 
                                                          conf_client.blinded_confirmation_tokens,
                                                          conf_client.signed_blinded_confirmation_tokens,
                                                          mock_confirmations_public_key);
          if (!mock_verified) {
            //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
            std::cerr << "ERROR: Mock confirmations proof invalid" << std::endl;
          }
          /////////////////////////////////////////////////////////


          /////////////////////////////////////////////////////////

          // happy_data: {"batchProof":"r2qx2h5ENHASgBxEhN2TjUjtC2L2McDN6g/lZ+nTaQ6q+6TZH0InhxRHIp0vdUlSbMMCHaPdLYsj/IJbseAtCw==","signedTokens":["VI27MCax4V9Gk60uC1dwCHHExHN2WbPwwlJk87fYAyo=","mhFmcWHLk5X8v+a/X0aea24OfGWsfAwWbP7RAeXXLV4="]}

          std::unique_ptr<base::Value> value(base::JSONReader::Read(get_resp));
          base::DictionaryValue* dict;
          if (!value->GetAsDictionary(&dict)) {
            std::cout << "2.3 get resp: no dict" << "\n";
            abort();
          }

          base::Value *v;

          if (!(v = dict->FindKey("batchProof"))) {
            std::cout << "2.3 no batchProof\n";
            abort();
          }

          std::string real_batch_proof = v->GetString();

          if (!(v = dict->FindKey("signedTokens"))) {
            std::cout << "2.3 no signedTokens\n";
            abort();
          }

          base::ListValue list(v->GetList());

          std::vector<std::string> real_server_sbc = {};

          for (size_t i = 0; i < list.GetSize(); i++) {
            base::Value *x;
            list.Get(i, &x);

            auto sbc = x->GetString();

            real_server_sbc.push_back(sbc);
          }

          mock_sbc = mock_server.signed_tokens;

          conf_client.step_2_4_storeTheSignedBlindedConfirmations(real_server_sbc);

          bool real_verified = conf_client.verifyBatchDLEQProof(real_batch_proof,
                                                          conf_client.blinded_confirmation_tokens,
                                                          conf_client.signed_blinded_confirmation_tokens,
                                                          conf_client.server_confirmation_key);
          if (!real_verified) {
            //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
            std::cerr << "ERROR: Server confirmations proof invalid" << std::endl;
          }
          /////////////////////////////////////////////////////////

        }

    }

    conf_client.mutex.unlock();
  }

  // reporting ad viewed
  {
    // TODO should we simply unblind signed tokens on receipt instead of waiting?
    //      we probably should
    //      we have to now basically because confirmations_ready_for_ad_showing now hinges on this

    conf_client.mutex.lock();
    conf_client.step_3_1a_unblindSignedBlindedConfirmations();

    conf_client.step_3_1b_generatePaymentTokenAndBlindIt();

    // // what's `t`? unblinded_signed_confirmation_token
    // std::cerr << "unblinded_signed_confirmation_token: " << (conf_client.unblinded_signed_confirmation_token) << "\n";
    // // what's `MAC_{sk}(R)`? item from blinded_payment_tokens
    // std::cerr << "blinded_payment_tokens: " << (conf_client.blinded_payment_tokens[0]) << "\n";

    std::string usct = conf_client.unblinded_signed_confirmation_token;
    std::string bpt = conf_client.blinded_payment_tokens[0];

    std::string prePaymentToken = bpt; 

    std::string json;
    
    // build body of POST request
    base::DictionaryValue dict;
    dict.SetKey("creativeInstanceId", base::Value(real_creative_instance_id));
    dict.SetKey("payload", base::Value(base::Value::Type::DICTIONARY));
    dict.SetKey("prePaymentToken", base::Value(prePaymentToken));
    dict.SetKey("type", base::Value("landed"));
    base::JSONWriter::Write(dict, &json);

    UnblindedToken restored_unblinded_token = UnblindedToken::decode_base64(usct);
    VerificationKey client_vKey = restored_unblinded_token.derive_verification_key();
    std::string message = json;
    VerificationSignature client_sig = client_vKey.sign(message);
    std::string base64_signature = client_sig.encode_base64();

    base::DictionaryValue bundle;
    std::string credential_json;
    bundle.SetKey("payload", base::Value(json));
    bundle.SetKey("signature", base::Value(base64_signature));
    bundle.SetKey("t", base::Value(usct));
    base::JSONWriter::Write(bundle, &credential_json);

std::cerr << "credential_json: " << (credential_json) << "\n";

    std::vector<uint8_t> vec(credential_json.begin(), credential_json.end());
    std::string b64_encoded_a = conf_client.getBase64(vec);

    std::string b64_encoded;
    base::Base64Encode(credential_json, &b64_encoded);

    DCHECK(b64_encoded_a == b64_encoded);

    std::string uri_encoded = net::EscapeQueryParamValue(b64_encoded, true);

std::cerr << "uri_encoded: " << (uri_encoded) << "\n";

    // 3 pieces we need for our POST request, 1 for URL, 1 for body, and 1 for URL that depends on body
    std::string confirmation_id = base::GenerateGUID();
    std::string real_body = json;
    std::string credential = uri_encoded;

    ///////////////////////////////////////////////////////////////////////
    // step_3_1c POST /v1/confirmation/{confirmation_id}/{credential}, which is (t, MAC_(sk)(R))
    happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
    conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );

    std::string endpoint = std::string("/v1/confirmation/").append(confirmation_id).append("/").append(credential);
std::cerr << "endpoint: " << (endpoint) << "\n";
    
    // -d "{ \"creativeInstanceId\": \"6ca04e53-2741-4d62-acbb-e63336d7ed46\", \"payload\": {}, \"prePaymentToken\": \"cgILwnP8ua+cZ+YHJUBq4h+U+mt6ip8lX9hzElHrSBg=\", \"type\": \"landed\" }"
    const char * h[] = {
                        "accept", "application/json",
                        "Content-Type", "application/json",
                        NULL, NULL };

    conn.request("POST", endpoint.c_str(), h, (const unsigned char *)real_body.c_str(), real_body.size());

    while( conn.outstanding() ) conn.pump();
    std::string post_resp = happy_data;
std::cerr << "post_resp: " << (post_resp) << "\n";
    ///////////////////////////////////////////////////////////////////////
exit(0);

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
    // TODO GET /v1/confirmation/{confirmation_id}/paymentToken
    // TODO on inet failure, retry or cleanup & unlock

    mock_server.generateSignedBlindedTokensAndProof(conf_client.blinded_payment_tokens);
    mock_sbp = mock_server.signed_tokens;
    mock_sbp_token = mock_sbp.front();
    mock_payment_proof = mock_server.batch_dleq_proof;

    conf_client.step_4_2_storeSignedBlindedPaymentToken(mock_sbp_token);

    bool mock_verified = conf_client.verifyBatchDLEQProof(mock_payment_proof, 
                                                     conf_client.blinded_payment_tokens,
                                                     conf_client.signed_blinded_payment_tokens,
                                                     mock_payments_public_key);
    if (!mock_verified) {
      //2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
      std::cerr << "ERROR: Mock payment proof invalid" << std::endl;
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
