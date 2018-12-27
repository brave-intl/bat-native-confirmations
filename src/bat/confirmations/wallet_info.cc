/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/confirmations/wallet_info.h"

namespace confirmations {

WalletInfo::WalletInfo() :
    payment_id(""),
    signing_key("") {}

WalletInfo::WalletInfo(const WalletInfo& info) :
    payment_id(info.payment_id),
    signing_key(info.signing_key) {}

WalletInfo::~WalletInfo() = default;

}  // namespace confirmations