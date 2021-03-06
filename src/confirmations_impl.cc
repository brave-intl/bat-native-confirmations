/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <time>
#include <utility>

#include "confirmations_impl.h"
#include "logging.h"
#include "static_values.h"
#include "refill_tokens.h"
#include "redeem_token.h"
#include "payout_tokens.h"
#include "unblinded_tokens.h"

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"

#include "third_party/re2/src/re2/re2.h"

using std::placeholders::_1;
using std::placeholders::_2;

namespace confirmations {

ConfirmationsImpl::ConfirmationsImpl(
    ConfirmationsClient* confirmations_client) :
    is_initialized_(false),
    unblinded_tokens_(std::make_unique<UnblindedTokens>(this)),
    unblinded_payment_tokens_(std::make_unique<UnblindedTokens>(this)),
    retry_getting_signed_tokens_timer_id_(0),
    refill_tokens_(std::make_unique<RefillTokens>(
        this, confirmations_client, unblinded_tokens_.get())),
    redeem_token_(std::make_unique<RedeemToken>(this, confirmations_client,
        unblinded_tokens_.get(), unblinded_payment_tokens_.get())),
    payout_redeemed_tokens_timer_id_(0),
    payout_tokens_(std::make_unique<PayoutTokens>(this, confirmations_client,
        unblinded_payment_tokens_.get())),
    confirmations_client_(confirmations_client) {
  BLOG(INFO) << "Initializing Confirmations";

  LoadState();
}

ConfirmationsImpl::~ConfirmationsImpl() {
  BLOG(INFO) << "Deinitializing Confirmations";

  StopRetryingToGetRefillSignedTokens();
  StopPayingOutRedeemedTokens();
}

void ConfirmationsImpl::CheckReady() {
  if (is_initialized_) {
    return;
  }

  if (!wallet_info_.IsValid() || catalog_issuers_.empty()) {
    return;
  }

  is_initialized_ = true;
  BLOG(INFO) << "Successfully initialized";

  PayoutRedeemedTokens();
  RefillTokensIfNecessary();
}

void ConfirmationsImpl::NotifyAdsIfConfirmationsIsReady() {
  bool is_ready = unblinded_tokens_->IsEmpty() ? false : true;
  confirmations_client_->SetConfirmationsIsReady(is_ready);
}

std::string ConfirmationsImpl::ToJSON() const {
  base::Value dictionary(base::Value::Type::DICTIONARY);

  // Catalog issuers
  auto catalog_issuers =
      GetCatalogIssuersAsDictionary(public_key_, catalog_issuers_);
  dictionary.SetKey("catalog_issuers", base::Value(std::move(catalog_issuers)));

  // Transaction history
  auto transaction_history =
      GetTransactionHistoryAsDictionary(transaction_history_);
  dictionary.SetKey("transaction_history", base::Value(
      std::move(transaction_history)));

  // Unblinded tokens
  auto unblinded_tokens = unblinded_tokens_->GetTokensAsList();
  dictionary.SetKey("unblinded_tokens", base::Value(
      std::move(unblinded_tokens)));

  // Unblinded payment tokens
  auto unblinded_payment_tokens = unblinded_payment_tokens_->GetTokensAsList();
  dictionary.SetKey("unblinded_payment_tokens", base::Value(
      std::move(unblinded_payment_tokens)));

  // Write to JSON
  std::string json;
  base::JSONWriter::Write(dictionary, &json);

  return json;
}

base::Value ConfirmationsImpl::GetCatalogIssuersAsDictionary(
    const std::string& public_key,
    const std::map<std::string, std::string>& issuers) const {
  base::Value dictionary(base::Value::Type::DICTIONARY);
  dictionary.SetKey("public_key", base::Value(public_key));

  base::Value list(base::Value::Type::LIST);
  for (const auto& issuer : issuers) {
    base::Value issuer_dictionary(base::Value::Type::DICTIONARY);

    issuer_dictionary.SetKey("name", base::Value(issuer.second));
    issuer_dictionary.SetKey("public_key", base::Value(issuer.first));

    list.GetList().push_back(std::move(issuer_dictionary));
  }

  dictionary.SetKey("issuers", base::Value(std::move(list)));

  return dictionary;
}

base::Value ConfirmationsImpl::GetTransactionHistoryAsDictionary(
    const std::vector<TransactionInfo>& transaction_history) const {
  base::Value dictionary(base::Value::Type::DICTIONARY);

  base::Value list(base::Value::Type::LIST);
  for (const auto& transaction : transaction_history) {
    base::Value transaction_dictionary(base::Value::Type::DICTIONARY);

    transaction_dictionary.SetKey("timestamp_in_seconds",
        base::Value(std::to_string(transaction.timestamp_in_seconds)));

    transaction_dictionary.SetKey("estimated_redemption_value",
        base::Value(transaction.estimated_redemption_value));

    list.GetList().push_back(std::move(transaction_dictionary));
  }

  dictionary.SetKey("transactions", base::Value(std::move(list)));

  return dictionary;
}

bool ConfirmationsImpl::FromJSON(const std::string& json) {
  std::unique_ptr<base::DictionaryValue> dictionary =
      base::DictionaryValue::From(base::JSONReader::Read(json));

  if (!dictionary) {
    BLOG(ERROR) << "Failed to parse JSON: " << json;
    return false;
  }

  // Catalog issuers
  auto* catalog_issuers_value = dictionary->FindKey("catalog_issuers");
  if (!catalog_issuers_value) {
    return false;
  }

  base::DictionaryValue* catalog_issuers_dictionary;
  if (!catalog_issuers_value->GetAsDictionary(&catalog_issuers_dictionary)) {
    return false;
  }

  std::string public_key;
  std::map<std::string, std::string> catalog_issuers;
  if (!GetCatalogIssuersFromDictionary(catalog_issuers_dictionary, &public_key,
      &catalog_issuers)) {
    return false;
  }

  // Transaction history
  auto* transaction_history_value = dictionary->FindKey("transaction_history");
  if (!transaction_history_value) {
    return false;
  }

  base::DictionaryValue* transaction_history_dictionary;
  if (!transaction_history_value->GetAsDictionary(
        &transaction_history_dictionary)) {
    return false;
  }

  std::vector<TransactionInfo> transaction_history;
  if (!GetTransactionHistoryFromDictionary(transaction_history_dictionary,
      &transaction_history)) {
    return false;
  }

  transaction_history_ = transaction_history;

  // Unblinded tokens
  auto* unblinded_tokens_value = dictionary->FindKey("unblinded_tokens");
  if (!unblinded_tokens_value) {
    return false;
  }

  base::ListValue unblinded_token_values(unblinded_tokens_value->GetList());

  // Unblinded payment tokens
  auto* unblinded_payment_tokens_value =
      dictionary->FindKey("unblinded_payment_tokens");
  if (!unblinded_payment_tokens_value) {
    return false;
  }

  base::ListValue unblinded_payment_token_values(
      unblinded_payment_tokens_value->GetList());

  // Update state
  public_key_ = public_key;
  catalog_issuers_ = catalog_issuers;
  unblinded_tokens_->SetTokensFromList(unblinded_token_values);
  unblinded_payment_tokens_->SetTokensFromList(unblinded_payment_token_values);

  return true;
}

bool ConfirmationsImpl::GetCatalogIssuersFromDictionary(
    base::DictionaryValue* dictionary,
    std::string* public_key,
    std::map<std::string, std::string>* issuers) const {
  DCHECK(dictionary);
  DCHECK(public_key);
  DCHECK(issuers);

  // Public key
  auto* public_key_value = dictionary->FindKey("public_key");
  if (!public_key_value) {
    return false;
  }
  *public_key = public_key_value->GetString();

  // Issuers
  auto* issuers_value = dictionary->FindKey("issuers");
  if (!issuers_value) {
    return false;
  }

  issuers->clear();
  base::ListValue issuers_list_value(issuers_value->GetList());
  for (auto& issuer_value : issuers_list_value) {
    base::DictionaryValue* issuer_dictionary;
    if (!issuer_value.GetAsDictionary(&issuer_dictionary)) {
      return false;
    }

    // Public key
    auto* public_key_value = issuer_dictionary->FindKey("public_key");
    if (!public_key_value) {
      return false;
    }
    auto public_key = public_key_value->GetString();

    // Name
    auto* name_value = issuer_dictionary->FindKey("name");
    if (!name_value) {
      return false;
    }
    auto name = name_value->GetString();

    issuers->insert({public_key, name});
  }

  return true;
}

bool ConfirmationsImpl::GetTransactionHistoryFromDictionary(
    base::DictionaryValue* dictionary,
    std::vector<TransactionInfo>* transaction_history) {
  DCHECK(dictionary);
  DCHECK(transaction_history);

  // Transaction
  auto* transactions_value = dictionary->FindKey("transactions");
  if (!transactions_value) {
    return false;
  }

  transaction_history->clear();
  base::ListValue transactions_list_value(transactions_value->GetList());
  for (auto& transaction_value : transactions_list_value) {
    base::DictionaryValue* transaction_dictionary;
    if (!transaction_value.GetAsDictionary(&transaction_dictionary)) {
      return false;
    }

    TransactionInfo info;

    // Timestamp
    auto* timestamp_in_seconds_value =
        transaction_dictionary->FindKey("timestamp_in_seconds");
    if (!timestamp_in_seconds_value) {
      return false;
    }
    info.timestamp_in_seconds =
        std::stoull(timestamp_in_seconds_value->GetString());

    // Estimated redemption value
    auto* estimated_redemption_value_value =
        transaction_dictionary->FindKey("estimated_redemption_value");
    if (!estimated_redemption_value_value) {
      return false;
    }
    info.estimated_redemption_value =
        estimated_redemption_value_value->GetDouble();

    transaction_history->push_back(info);
  }

  return true;
}

void ConfirmationsImpl::SaveState() {
  BLOG(INFO) << "Saving confirmations state";

  std::string json = ToJSON();
  auto callback = std::bind(&ConfirmationsImpl::OnStateSaved, this, _1);
  confirmations_client_->SaveState(_confirmations_name, json, callback);

  NotifyAdsIfConfirmationsIsReady();
}

void ConfirmationsImpl::OnStateSaved(const Result result) {
  if (result != SUCCESS) {
    BLOG(ERROR) << "Failed to save confirmations state";
    return;
  }

  BLOG(INFO) << "Successfully saved confirmations state";
}

void ConfirmationsImpl::LoadState() {
  BLOG(INFO) << "Loading confirmations state";

  auto callback = std::bind(&ConfirmationsImpl::OnStateLoaded, this, _1, _2);
  confirmations_client_->LoadState(_confirmations_name, callback);
}

void ConfirmationsImpl::OnStateLoaded(
    const Result result,
    const std::string& json) {
  auto confirmations_json = json;

  if (result != SUCCESS) {
    BLOG(ERROR) << "Failed to load confirmations state, resetting to default"
        << " values";

    confirmations_json = ToJSON();
  }

  if (!FromJSON(confirmations_json)) {
    BLOG(ERROR) << "Failed to parse confirmations state: "
        << confirmations_json;
    return;
  }

  BLOG(INFO) << "Successfully loaded confirmations state";

  NotifyAdsIfConfirmationsIsReady();

  CheckReady();
}

void ConfirmationsImpl::ResetState() {
  BLOG(INFO) << "Resetting confirmations to default state";

  auto callback = std::bind(&ConfirmationsImpl::OnStateReset, this, _1);
  confirmations_client_->ResetState(_confirmations_name, callback);
}

void ConfirmationsImpl::OnStateReset(const Result result) {
  if (result != SUCCESS) {
    BLOG(ERROR) << "Failed to reset confirmations state";

    return;
  }

  BLOG(INFO) << "Successfully reset confirmations state";
}

void ConfirmationsImpl::SetWalletInfo(std::unique_ptr<WalletInfo> info) {
  if (info->payment_id.empty() || info->public_key.empty()) {
    return;
  }

  wallet_info_ = WalletInfo(*info);

  BLOG(INFO) << "SetWalletInfo:";
  BLOG(INFO) << "  Payment id: " << wallet_info_.payment_id;
  BLOG(INFO) << "  Public key: " << wallet_info_.public_key;

  CheckReady();
}

void ConfirmationsImpl::SetCatalogIssuers(std::unique_ptr<IssuersInfo> info) {
  BLOG(INFO) << "SetCatalogIssuers:";
  BLOG(INFO) << "  Public key: " << info->public_key;
  BLOG(INFO) << "  Issuers:";

  for (const auto& issuer : info->issuers) {
    BLOG(INFO) << "    Name: " << issuer.name;
    BLOG(INFO) << "    Public key: " << issuer.public_key;
  }

  public_key_ = info->public_key;

  catalog_issuers_.clear();
  for (const auto& issuer : info->issuers) {
    catalog_issuers_.insert({issuer.public_key, issuer.name});
  }

  SaveState();

  CheckReady();
}

std::map<std::string, std::string> ConfirmationsImpl::GetCatalogIssuers()
    const {
  return catalog_issuers_;
}

bool ConfirmationsImpl::IsValidPublicKeyForCatalogIssuers(
    const std::string& public_key) const {
  auto it = catalog_issuers_.find(public_key);
  if (it == catalog_issuers_.end()) {
    return false;
  }

  return true;
}

void ConfirmationsImpl::GetTransactionHistory(
    const uint64_t from_timestamp_in_seconds,
    const uint64_t to_timestamp_in_seconds,
    OnGetTransactionHistoryCallback callback) {
  std::vector<TransactionInfo> transactions(transaction_history_.size());

  auto it = std::copy_if(transaction_history_.begin(),
      transaction_history_.end(), transactions.begin(),
      [=](TransactionInfo& info) {
        return info.timestamp_in_seconds >= from_timestamp_in_seconds &&
            info.timestamp_in_seconds <= to_timestamp_in_seconds;
      });

  transactions.resize(std::distance(transactions.begin(), it));

  auto transactions_info = std::make_unique<TransactionsInfo>();
  transactions_info->transactions = transactions;

  callback(std::move(transactions_info));
}

double ConfirmationsImpl::GetEstimatedRedemptionValue(
    const std::string& public_key) const {
  double estimated_redemption_value = 0.0;

  auto it = catalog_issuers_.find(public_key);
  if (it != catalog_issuers_.end()) {
    auto name = it->second;
    if (!re2::RE2::Replace(&name, "BAT", "")) {
      BLOG(ERROR) << "Could not estimate redemption value due to catalog"
      << " issuer name missing BAT";
    }

    estimated_redemption_value = stod(name);
  }

  return estimated_redemption_value;
}

void ConfirmationsImpl::AppendEstimatedRedemptionValueToTransactionHistory(
    double estimated_redemption_value) {
  TransactionInfo info;
  info.timestamp_in_seconds = static_cast<uint64_t>(std::time(nullptr));
  info.estimated_redemption_value = estimated_redemption_value;

  transaction_history_.push_back(info);

  SaveState();
}

void ConfirmationsImpl::AdSustained(std::unique_ptr<NotificationInfo> info) {
  BLOG(INFO) << "AdSustained:";
  BLOG(INFO) << "  creativeSetId: " << info->creative_set_id;
  BLOG(INFO) << "  category: " << info->category;
  BLOG(INFO) << "  notificationUrl: " << info->url;
  BLOG(INFO) << "  notificationText: " << info->text;
  BLOG(INFO) << "  advertiser: " << info->advertiser;
  BLOG(INFO) << "  uuid: " << info->uuid;

  redeem_token_->Redeem(info->uuid);
}

bool ConfirmationsImpl::OnTimer(const uint32_t timer_id) {
  BLOG(INFO) << "OnTimer:" << std::endl
      << "  timer_id: "
      << timer_id << std::endl
      << "  retry_getting_signed_tokens_timer_id_: "
      << retry_getting_signed_tokens_timer_id_ << std::endl
      << "  payout_redeemed_tokens_timer_id_: "
      << payout_redeemed_tokens_timer_id_;

  if (timer_id == retry_getting_signed_tokens_timer_id_) {
    RetryGettingRefillSignedTokens();
    return true;
  } else if (timer_id == payout_redeemed_tokens_timer_id_) {
    PayoutRedeemedTokens();
    return true;
  }

  return false;
}

void ConfirmationsImpl::RefillTokensIfNecessary() const {
  refill_tokens_->Refill(wallet_info_, public_key_);
}

void ConfirmationsImpl::StartPayingOutRedeemedTokens(
    const uint64_t start_timer_in) {
  StopPayingOutRedeemedTokens();

  confirmations_client_->SetTimer(start_timer_in,
      &payout_redeemed_tokens_timer_id_);
  if (payout_redeemed_tokens_timer_id_ == 0) {
    BLOG(ERROR)
        << "Failed to start paying out redeemed tokens due to an invalid timer";
    return;
  }

  BLOG(INFO) << "Start paying out redeemed tokens in " << start_timer_in
      << " seconds";
}

void ConfirmationsImpl::PayoutRedeemedTokens() const {
  payout_tokens_->Payout(wallet_info_);
}

void ConfirmationsImpl::StopPayingOutRedeemedTokens() {
  if (!IsPayingOutRedeemedTokens()) {
    return;
  }

  BLOG(INFO) << "Stopped paying out redeemed tokens";

  confirmations_client_->KillTimer(payout_redeemed_tokens_timer_id_);
  payout_redeemed_tokens_timer_id_ = 0;
}

bool ConfirmationsImpl::IsPayingOutRedeemedTokens() const {
  if (payout_redeemed_tokens_timer_id_ == 0) {
    return false;
  }

  return true;
}

void ConfirmationsImpl::StartRetryingToGetRefillSignedTokens(
    const uint64_t start_timer_in) {
  StopRetryingToGetRefillSignedTokens();

  confirmations_client_->SetTimer(start_timer_in,
      &retry_getting_signed_tokens_timer_id_);
  if (retry_getting_signed_tokens_timer_id_ == 0) {
    BLOG(ERROR)
        << "Failed to start getting signed tokens due to an invalid timer";

    return;
  }

  BLOG(INFO) << "Start getting signed tokens in " << start_timer_in
      << " seconds";
}

void ConfirmationsImpl::RetryGettingRefillSignedTokens() const {
  refill_tokens_->RetryGettingSignedTokens();
}

void ConfirmationsImpl::StopRetryingToGetRefillSignedTokens() {
  if (!IsRetryingToGetRefillSignedTokens()) {
    return;
  }

  BLOG(INFO) << "Stopped getting signed tokens";

  confirmations_client_->KillTimer(retry_getting_signed_tokens_timer_id_);
  retry_getting_signed_tokens_timer_id_ = 0;
}

bool ConfirmationsImpl::IsRetryingToGetRefillSignedTokens() const {
  if (retry_getting_signed_tokens_timer_id_ == 0) {
    return false;
  }

  return true;
}

}  // namespace confirmations
