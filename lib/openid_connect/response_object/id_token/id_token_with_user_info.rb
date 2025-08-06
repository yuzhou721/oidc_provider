# frozen_string_literal: true

module OpenIDConnect
  class ResponseObject
    class IdTokenWithUserInfo < IdToken
      attr_optional :email, :email_verified, :given_name, :family_name

    end
  end
  end
