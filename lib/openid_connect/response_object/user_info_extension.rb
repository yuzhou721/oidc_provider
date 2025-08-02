# frozen_string_literal: true

module OpenIDConnect
  class ResponseObject
    class UserInfoExtension < UserInfo
      attr_accessor :nonce

      def initialize(attributes = {})
        super(attributes)
        @nonce = attributes[:nonce] if attributes.key?(:nonce)
      end
    end
  end
end