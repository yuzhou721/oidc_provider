# frozen_string_literal: true

module OpenIDConnect
  class ResponseObject
    class UserInfoWithNonce < UserInfo
      attr_required :nonce

    end
  end
end