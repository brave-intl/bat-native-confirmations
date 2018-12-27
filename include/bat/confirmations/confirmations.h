/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BAT_CONFIRMATIONS_CONFIRMATIONS_H_
#define BAT_CONFIRMATIONS_CONFIRMATIONS_H_

#include "bat/confirmations/confirmations_client.h"
#include "bat/confirmations/export.h"
#include "bat/confirmations/notification_info.h"
#include "bat/confirmations/issuers_info.h"
#include "bat/confirmations/wallet_info.h"

namespace confirmations {

// Determines whether to use the staging or production Ad Serve
extern bool _is_production;

extern const char _confirmations_name[];

class CONFIRMATIONS_EXPORT Confirmations {
 public:
  Confirmations() = default;
  virtual ~Confirmations() = default;

  static Confirmations* CreateInstance(
    ConfirmationsClient* confirmations_client);

  // Should be called to set wallet information for payments
  virtual void SetWalletInfo(std::unique_ptr<WalletInfo> info) = 0;

  // Should be called when a new catalog has been downloaded in Brave Ads
  virtual void SetCatalogIssuers(std::unique_ptr<IssuersInfo> info) = 0;

  // Should be called to determine if Confirmations is ready to show ads
  bool IsReadyToShowAds();

  // Should be called when an ad is sustained in Brave Ads
  virtual void AdSustained(std::unique_ptr<NotificationInfo> info) = 0;

  // Should be called when a timer is triggered
  virtual void OnTimer(const uint32_t timer_id) = 0;

 private:
  // Not copyable, not assignable
  Confirmations(const Confirmations&) = delete;
  Confirmations& operator=(const Confirmations&) = delete;
};

}  // namespace confirmations

#endif  // BAT_CONFIRMATIONS_CONFIRMATIONS_H_