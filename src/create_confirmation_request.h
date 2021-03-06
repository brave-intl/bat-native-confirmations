/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BAT_CONFIRMATIONS_CREATE_CONFIRMATION_REQUEST_H_
#define BAT_CONFIRMATIONS_CREATE_CONFIRMATION_REQUEST_H_

#include <string>
#include <vector>

#include "bat/confirmations/confirmations_client.h"

#include "wrapper.hpp"

using challenge_bypass_ristretto::BlindedToken;
using challenge_bypass_ristretto::UnblindedToken;

namespace confirmations {

class CreateConfirmationRequest {
 public:
  CreateConfirmationRequest();
  ~CreateConfirmationRequest();

  std::string BuildUrl(
    const std::string& confirmation_id,
    const std::string& credential) const;

  URLRequestMethod GetMethod() const;

  std::string BuildBody(
      const std::string& payload) const;

  std::vector<std::string> BuildHeaders() const;
  std::string GetAcceptHeaderValue() const;

  std::string GetContentType() const;

  std::string CreateConfirmationRequestDTO(
      const std::string& creative_instance_id,
      const BlindedToken& token) const;

  std::string CreateCredential(
      const UnblindedToken& token,
      const std::string& payload) const;
};

}  // namespace confirmations

#endif  // BAT_CONFIRMATIONS_CREATE_CONFIRMATION_REQUEST_H_
