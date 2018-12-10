#include "confirmations.hpp"

#include <vector>
#include <iostream>
#include <memory>

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"

#include "tweetnacl.h"
#include <openssl/base64.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/sha.h>


void OnBegin( const happyhttp::Response* r, void* userdata )
{
  // printf("BEGIN (%d %s)\n", r->getstatus(), r->getreason() );
  count = 0;
  happy_data = "";
  happy_status = r->getstatus();
}

void OnData( const happyhttp::Response* r, void* userdata, const unsigned char* data, int n )
{
  //fwrite( data,1,n, stdout );
  happy_data.append((char *)data, (size_t)n);
  count += n;
}

void OnComplete( const happyhttp::Response* r, void* userdata )
{
  happy_status = r->getstatus();
  // printf("END (%d %s)\n", r->getstatus(), r->getreason() );
  // printf("COMPLETE (%d bytes)\n", count );
}


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

  void vector_concat(std::vector<std::string> &dest, std::vector<std::string> &source) {
    dest.insert(dest.end(), source.begin(), source.end());
  }

  bool Confirmations::confirmations_ready_for_ad_showing() {

    // TODO Whatever thread/service calls this in brave-core-client must also 
    //      be the one that triggers ad showing, or we'll have a race condition
    mutex.lock();
    bool ready = (signed_blinded_confirmation_tokens.size() > 0);
    mutex.unlock();

    return ready;
  }

  void Confirmations::step_1_1_storeTheServersConfirmationsPublicKeyAndGenerator(std::string confirmations_GH_pair, std::string payments_GH_pair, std::vector<std::string> bat_names, std::vector<std::string> bat_keys) {
    this->mutex.lock();
    // This (G,H) *pair* is exposed as a *single* string via the rust lib
    // G is the generator the server used in H, see next line
    // H, aka Y, is xG, the server's public key
    // These are both necessary for the DLEQ proof, but not useful elsewhere
    // These come back with the catalog from the server
    // Later we'll get an *array of pairs* for the payments side
    this->server_confirmation_key = confirmations_GH_pair;
    this->server_payment_key = payments_GH_pair;
    this->server_bat_payment_names = bat_names;
    this->server_bat_payment_keys = bat_keys;
  
    // for(auto x : bat_names) { std::cerr << "x: " << (x) << "\n"; }
  
    this->saveState();
    std::cout << "step1.1 key: " << this->server_confirmation_key << std::endl;
    this->mutex.unlock();
  }

  void Confirmations::step_2_refillConfirmationsIfNecessary(std::string real_wallet_address,
                                                            std::string real_wallet_address_secret_key,
                                                            std::string local_server_confirmation_key) {

    this->mutex.lock();

    if (this->blinded_confirmation_tokens.size() > low_token_threshold) {
      return;
    }

    std::vector<std::string> local_original_confirmation_tokens = {};
    std::vector<std::string> local_blinded_confirmation_tokens = {};

    size_t needed = refill_amount - blinded_confirmation_tokens.size();

    for (size_t i = 0; i < needed; i++) {
      // client prepares a random token and blinding scalar pair
      Token token = Token::random();
      std::string token_base64 = token.encode_base64();

      // client blinds the token
      BlindedToken blinded_token = token.blind();
      std::string blinded_token_base64 = blinded_token.encode_base64();

      // client stores the original token and the blinded token
      // will send blinded token to server
      local_original_confirmation_tokens.push_back(token_base64);
      local_blinded_confirmation_tokens.push_back(blinded_token_base64);
    }
  
    std::cout << "step2.1: batch generate, count: " << local_original_confirmation_tokens.size() << std::endl;

    {
      std::string digest = "digest";
      std::string primary = "primary";
      
      /////////////////////////////////////////////////////////////////////////////
      std::string build = "";
      
      build.append("{\"blindedTokens\":");
      build.append("[");
      std::vector<std::string> a = local_blinded_confirmation_tokens;
      
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
      
      std::vector<uint8_t> real_sha_raw = this->getSHA256(real_body);
      std::string real_body_sha_256_b64 = this->getBase64(real_sha_raw);
      
      std::vector<uint8_t> real_skey = this->rawDataBytesVectorFromASCIIHexString(real_wallet_address_secret_key);
      
      std::string real_digest_field = std::string("SHA-256=").append(real_body_sha_256_b64);

      std::string real_signature_field = this->sign(&digest, &real_digest_field, 1, primary, real_skey);
      /////////////////////////////////////////////////////////////////////////////

      happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
      conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );

      // step 2.2 POST /v1/confirmation/token/{payment_id}

      std::cout << "step2.2: POST /v1/confirmation/token/{payment_id}: " << real_wallet_address << std::endl;
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
 
      // TODO 2.2 POST: on inet failure, retry or cleanup & unlock
      
      std::unique_ptr<base::Value> value(base::JSONReader::Read(post_resp));
      base::DictionaryValue* dict;
      if (!value->GetAsDictionary(&dict)) {
        std::cerr << "2.2 post resp: no dict" << "\n";
        return;
      }
 
      base::Value *v;
      if (!(v = dict->FindKey("nonce"))) {
        std::cerr << "2.2 no nonce\n";
        return;
      }
 
      std::string nonce = v->GetString();
 
      // TODO Instead of pursuing true asynchronicity at this point, what we can do is sleep for a minute or two
      //      and blow away any work to this point on failure
      //      this solves the problem for now since the tokens have no value at this point
 
      //STEP 2.3
      // TODO this is done blocking and assumes success but we need to separate it more and account for the possibility of failures
      // TODO GET: on inet failure, retry or cleanup & unlock
      { 
        std::cout << "step2.3: GET  /v1/confirmation/token/{payment_id}?nonce=: " << nonce << std::endl;
        happyhttp::Connection conn(BRAVE_AD_SERVER, BRAVE_AD_SERVER_PORT);
        conn.setcallbacks( OnBegin, OnData, OnComplete, 0 );
 
        // /v1/confirmation/token/{payment_id}
        std::string endpoint = std::string("/v1/confirmation/token/").append(real_wallet_address).append("?nonce=").append(nonce);

        conn.request("GET", endpoint.c_str()  ); // h, (const unsigned char *)real_body.c_str(), real_body.size());

        while( conn.outstanding() ) conn.pump();
        std::string get_resp = happy_data;

        /////////////////////////////////////////////////////////

        // happy_data: {"batchProof":"r2qx2h5ENHASgBxEhN2TjUjtC2L2McDN6g/lZ+nTaQ6q+6TZH0InhxRHIp0vdUlSbMMCHaPdLYsj/IJbseAtCw==","signedTokens":["VI27MCax4V9Gk60uC1dwCHHExHN2WbPwwlJk87fYAyo=","mhFmcWHLk5X8v+a/X0aea24OfGWsfAwWbP7RAeXXLV4="]}

        std::unique_ptr<base::Value> value(base::JSONReader::Read(get_resp));
        base::DictionaryValue* dict;
        if (!value->GetAsDictionary(&dict)) {
          std::cerr << "2.3 get resp: no dict" << "\n";
          return;
        }

        base::Value *v;

        if (!(v = dict->FindKey("batchProof"))) {
          std::cerr << "2.3 no batchProof\n";
          return;
        }

        std::string real_batch_proof = v->GetString();

        if (!(v = dict->FindKey("signedTokens"))) {
          std::cerr << "2.3 no signedTokens\n";
          return;
        }

        base::ListValue list(v->GetList());

        std::vector<std::string> server_signed_blinded_confirmations = {};

        for (size_t i = 0; i < list.GetSize(); i++) {
          base::Value *x;
          list.Get(i, &x);

          auto sbc = x->GetString();

          server_signed_blinded_confirmations.push_back(sbc);
        }

        bool real_verified = this->verifyBatchDLEQProof(real_batch_proof,
                                                        local_blinded_confirmation_tokens,
                                                        server_signed_blinded_confirmations,
                                                        local_server_confirmation_key);
        if (!real_verified) {
          // 2018.11.29 kevin - ok to log these only (maybe forever) but don't consider failing until after we're versioned on "issuers" private keys 
          // 2018.12.10 actually, ok to fail on the confirmations portion of this now. we don't want bad tokens anyway
          std::cerr << "ERROR: Server confirmations proof invalid" << std::endl;
          return;
        }

        {
          //finally, if everything succeeded we'll modify object state and persist
          std::cout << "step2.4: store the signed blinded confirmations tokens & pre data" << std::endl;
          vector_concat(this->original_confirmation_tokens, local_original_confirmation_tokens);
          vector_concat(this->blinded_confirmation_tokens, local_blinded_confirmation_tokens);
          vector_concat(this->signed_blinded_confirmation_tokens, server_signed_blinded_confirmations);
          this->saveState();
        }

      } // 2.3

     } // 2.1
 
    this->mutex.unlock();
  }

  void Confirmations::step_3_1a_unblindSignedBlindedConfirmations() {

    if (this->signed_blinded_confirmation_tokens.size() <= 0) {
      std::cout << "ERROR: step_3_1a, no signed blinded confirmation tokens" << std::endl;
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

  void Confirmations::step_3_2_storeConfirmationId(std::string confirmationId) {

    this->confirmation_id = confirmationId;

    this->saveState();
    std::cout << "step3.2: store confirmationId" << std::endl;
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
      std::cout << "ERROR: step_5_1, no signed blinded payment tokens" << std::endl;
      return;
    }

    // TODO this can't be good. figure out how to remove old tokens based on success
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

    std::cout << "step5.1 unblind signed blinded payments" << std::endl;
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

  std::unique_ptr<base::ListValue> munge(std::vector<std::string> v) {

    base::ListValue * list = new base::ListValue();

    for (auto x : v) {
      list->AppendString(x);
    }

    return std::unique_ptr<base::ListValue>(list); 
  }

  std::vector<std::string> Confirmations::unmunge(base::Value *value) {
    std::vector<std::string> v;

    base::ListValue list(value->GetList());

    for (size_t i = 0; i < list.GetSize(); i++) {
      base::Value *x;
      list.Get(i, &x);
      v.push_back(x->GetString());
    }

    return v;
  }

  std::string Confirmations::toJSONString() {
    base::DictionaryValue dict;
     
    dict.SetKey("issuers_version", base::Value(issuers_version));
    dict.SetKey("server_confirmation_key", base::Value(server_confirmation_key));
    dict.SetKey("server_payment_key", base::Value(server_payment_key));
    dict.SetWithoutPathExpansion("server_bat_payment_names", munge(server_bat_payment_names));
    dict.SetWithoutPathExpansion("server_bat_payment_keys", munge(server_bat_payment_keys));
    dict.SetWithoutPathExpansion("original_confirmation_tokens", munge(original_confirmation_tokens));
    dict.SetWithoutPathExpansion("blinded_confirmation_tokens", munge(blinded_confirmation_tokens));
    dict.SetWithoutPathExpansion("signed_blinded_confirmation_tokens", munge(signed_blinded_confirmation_tokens));
    dict.SetKey("unblinded_signed_confirmation_token", base::Value(unblinded_signed_confirmation_token));
    dict.SetWithoutPathExpansion("original_payment_tokens", munge(original_payment_tokens));
    dict.SetWithoutPathExpansion("blinded_payment_tokens", munge(blinded_payment_tokens));
    dict.SetWithoutPathExpansion("signed_blinded_payment_tokens", munge(signed_blinded_payment_tokens));
    dict.SetWithoutPathExpansion("unblinded_signed_payment_tokens", munge(unblinded_signed_payment_tokens));
    dict.SetKey("confirmation_id", base::Value(confirmation_id));
    dict.SetKey("estimated_payment_worth", base::Value(estimated_payment_worth));

    std::string json;
    base::JSONWriter::Write(dict, &json);

    //std::unique_ptr<base::Value> val( base::JSONReader::Read(json) );
    //assert(dict.Equals(val.get()));

    return json;
  }

  bool Confirmations::fromJSONString(std::string json_string) {
    bool fail = 0;
    bool succeed = 1;

    std::unique_ptr<base::Value> value(base::JSONReader::Read(json_string));

    if (!value) {
      return fail;
    }

    base::DictionaryValue* dict;
    if (!value->GetAsDictionary(&dict)) {
      return fail;
    }

    base::Value *v;
    //std::cerr << "v: " << v->GetString() << "\n";

    // if (!(v = dict->FindKey(""))) return fail;
    // this->= v->GetString();

    if (!(v = dict->FindKey("issuers_version"))) return fail;
    this->issuers_version = v->GetString();

    if (!(v = dict->FindKey("server_confirmation_key"))) return fail;
    this->server_confirmation_key = v->GetString();

    if (!(v = dict->FindKey("server_payment_key"))) return fail;
    this->server_payment_key = v->GetString();

    if (!(v = dict->FindKey("server_bat_payment_names"))) return fail;
    this->server_bat_payment_names = unmunge(v);

    if (!(v = dict->FindKey("server_bat_payment_keys"))) return fail;
    this->server_bat_payment_keys = unmunge(v);

    if (!(v = dict->FindKey("original_confirmation_tokens"))) return fail;
    this->original_confirmation_tokens = unmunge(v);

    if (!(v = dict->FindKey("blinded_confirmation_tokens"))) return fail;
    this->blinded_confirmation_tokens = unmunge(v);

    if (!(v = dict->FindKey("signed_blinded_confirmation_tokens"))) return fail;
    this->signed_blinded_confirmation_tokens = unmunge(v);

    if (!(v = dict->FindKey("unblinded_signed_confirmation_token"))) return fail;
    this->unblinded_signed_confirmation_token = v->GetString();

    if (!(v = dict->FindKey("original_payment_tokens"))) return fail;
    this->original_payment_tokens = unmunge(v);

    if (!(v = dict->FindKey("blinded_payment_tokens"))) return fail;
    this->blinded_payment_tokens = unmunge(v);

    if (!(v = dict->FindKey("signed_blinded_payment_tokens"))) return fail;
    this->signed_blinded_payment_tokens = unmunge(v);

    if (!(v = dict->FindKey("unblinded_signed_payment_tokens"))) return fail;
    this->unblinded_signed_payment_tokens = unmunge(v);

    if (!(v = dict->FindKey("confirmation_id"))) return fail;
    this->confirmation_id = v->GetString();

    if (!(v = dict->FindKey("estimated_payment_worth"))) return fail;
    this->estimated_payment_worth = v->GetString();

    return succeed;
  }

  void Confirmations::saveState() {
    // TODO: call out to client
    std::string json = toJSONString();

    assert(this->fromJSONString(json));
    //this->server_confirmation_key = "bort";
    std::string json2 = toJSONString();
    assert(json2 == json);

    // std::cout << json<< "\n\n\n\n";
    // std::cout << "saving state... | ";
  }

  bool Confirmations::loadState(std::string json_state) {
    // returns false on failure to load (eg, malformed json)
    // TODO: call out to client?

    bool fail = 0;
    bool succeed = 1;

    bool parsed = this->fromJSONString(json_state);

    if (!parsed) {
      return fail;
    }

    std::cout << "loading state... | ";

    return succeed;
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

  std::string Confirmations::BATNameFromBATPublicKey(std::string token) {
    std::vector<std::string> &k = this->server_bat_payment_keys;

    // find position of public key in the BAT array  (later use same pos to find the `name`)
    ptrdiff_t pos = distance(k.begin(), find(k.begin(), k.end(), token));

    bool found = pos < (ptrdiff_t)k.size();

    if (!found) {
      return "";
    }

    std::string name = this->server_bat_payment_names[pos];
    return name;
  }

  MockServer::~MockServer() {

  }

  MockServer::MockServer() {

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

  std::string Confirmations::sign(std::string* keys, std::string* values, const unsigned int& size,
       const std::string& keyId, const std::vector<uint8_t>& secretKey) {
     std::string headers;
     std::string message;
     for (unsigned int i = 0; i < size; i++) {
       if (0 != i) {
         headers += " ";
         message += "\n";
       }
       headers += keys[i];
       message += keys[i] + ": " + values[i];
     }
     std::vector<uint8_t> signedMsg(crypto_sign_BYTES + message.length());

     unsigned long long signedMsgSize = 0;
     crypto_sign(&signedMsg.front(), &signedMsgSize, (const unsigned char*)message.c_str(), (unsigned long long)message.length(), &secretKey.front());

     std::vector<uint8_t> signature(crypto_sign_BYTES);
     std::copy(signedMsg.begin(), signedMsg.begin() + crypto_sign_BYTES, signature.begin());

     return "keyId=\"" + keyId + "\",algorithm=\"" + CONFIRMATIONS_SIGNATURE_ALGORITHM +
       "\",headers=\"" + headers + "\",signature=\"" + getBase64(signature) + "\"";
  }


  std::vector<uint8_t> Confirmations::getSHA256(const std::string& in) {
    std::vector<uint8_t> res(SHA256_DIGEST_LENGTH);
    SHA256((uint8_t*)in.c_str(), in.length(), &res.front());
    return res;
  }

  std::string Confirmations::getBase64(const std::vector<uint8_t>& in) {
    std::string res;
    size_t size = 0;
    if (!EVP_EncodedLength(&size, in.size())) {
      DCHECK(false);
      LOG(ERROR) << "EVP_EncodedLength failure in getBase64";

      return "";
    }
    std::vector<uint8_t> out(size);
    int numEncBytes = EVP_EncodeBlock(&out.front(), &in.front(), in.size());
    DCHECK(numEncBytes != 0);
    res = (char*)&out.front();
    return res;
  }

  std::vector<uint8_t> Confirmations::rawDataBytesVectorFromASCIIHexString(std::string ascii) {
    std::vector<uint8_t> bytes;
    size_t len = ascii.length();
    for(size_t i = 0; i < len; i += 2) {
        std::string b =  ascii.substr(i, 2);
        uint8_t x = std::strtol(b.c_str(),0,16);
        bytes.push_back(x);
    }
    return bytes;
  }


}
