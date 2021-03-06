/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ads_serve_helper.h"
#include "static_values.h"
#include "bat/confirmations/confirmations.h"

namespace helper {

std::string AdsServe::GetURL() {
  if (confirmations::_is_production) {
    return BAT_ADS_PRODUCTION_SERVER;
  } else {
    return BAT_ADS_STAGING_SERVER;
  }
}

}  // namespace helper
