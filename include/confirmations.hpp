#pragma once
#include <mutex>
#include "wrapper.hpp"
#include "base/values.h"

#define CONFIRMATIONS_SIGNATURE_ALGORITHM "ed25519"

#include "happyhttp.h" // TODO brave-core-client: remove all traces

static const char* BRAVE_AD_SERVER = "ads-serve.bravesoftware.com";
static int BRAVE_AD_SERVER_PORT = 80;
extern int count;
extern std::string happy_data; 
extern int happy_status;
void OnBegin( const happyhttp::Response* r, void* userdata );
void OnData( const happyhttp::Response* r, void* userdata, const unsigned char* data, int n );
void OnComplete( const happyhttp::Response* r, void* userdata );

namespace bat_native_confirmations {

using namespace challenge_bypass_ristretto;

class Confirmations {
  public:
    std::mutex mutex;

    const size_t low_token_threshold = 2; // 20 
    const size_t refill_amount = 1 * low_token_threshold; // 5

    ////////////////////////////////////////
    // persist these properties
    std::string issuers_version = "0"; // if unset or "0", assume we haven't gotten one
    std::string server_confirmation_key; // 2018.12.10 If this changes what we can do is burn .*confirmation_tokens.* & repop
    std::string server_payment_key; // per amir,evq, this key isn't supposed to exist
    std::vector<std::string> server_bat_payment_names;
    std::vector<std::string> server_bat_payment_keys;

    std::vector<std::string>       original_confirmation_tokens;
    std::vector<std::string>        blinded_confirmation_tokens;
    std::vector<std::string> signed_blinded_confirmation_tokens;

    std::vector<std::string>                payment_token_json_bundles;
    std::vector<std::string> signed_blinded_payment_token_json_bundles;
    std::vector<std::string>           fully_submitted_payment_bundles;
    ////////////////////////////////////////

    void test();
    bool confirmations_ready_for_ad_showing();
    void step_1_storeTheServersConfirmationsPublicKeyAndGenerator(std::string confirmations_GH_pair,
                                                                  std::string payments_GH_pair,
                                                                  std::vector<std::string> bat_names,
                                                                  std::vector<std::string> bat_keys);
    void step_2_refillConfirmationsIfNecessary(std::string real_wallet_address,
                                               std::string real_wallet_address_secret_key,
                                               std::string server_confirmation_key);
    void step_3_redeemConfirmation(std::string real_creative_instance_id);
    void step_4_retrievePaymentIOUs();
    void step_5_cashInPaymentIOUs(std::string real_wallet_address);

    bool verifyBatchDLEQProof(std::string proof_string, 
                              std::vector<std::string> blind_strings,
                              std::vector<std::string> signed_strings,
                              std::string public_key_string);

    void popFrontConfirmation();
    void popFrontPayment();
    void saveState();
    bool loadState(std::string json_state);
    std::string toJSONString();
    bool fromJSONString(std::string json);
    std::vector<std::string> unmunge(base::Value *value);
    std::string BATNameFromBATPublicKey(std::string token);
    bool processIOUBundle(std::string bundle_json);

    //convert std::string of ascii-hex to raw data vector<uint8_t>
    std::vector<uint8_t> rawDataBytesVectorFromASCIIHexString(std::string ascii);

    // these functions are copy-pasta from the ledger library and in the future should be refactored somehow.
    std::string sign(std::string* keys, std::string* values, const unsigned int& size, const std::string& keyId, const std::vector<uint8_t>& secretKey);
    std::vector<uint8_t> getSHA256(const std::string& in);
    std::string getBase64(const std::vector<uint8_t>& in);

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
