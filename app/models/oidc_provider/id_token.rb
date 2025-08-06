# frozen_string_literal: true

module OIDCProvider
  class IdToken < ApplicationRecord
    PASSPHRASE_ENV_VAR = 'OIDC_PROVIDER_KEY_PASSPHRASE'

    belongs_to :authorization

    attribute :expires_at, :datetime, default: -> { 1.hour.from_now }

    delegate :account, to: :authorization

    def to_response_object
      if OIDCProvider.include_user_claims_in_id_token
        OpenIDConnect::ResponseObject::IdTokenWithUserInfo.new(
          iss: OIDCProvider.issuer,
          sub: account.send(OIDCProvider.account_identifier),
          aud: authorization.client_id,
          nonce: nonce,
          exp: expires_at.to_i,
          iat: created_at.to_i,
          auth_time:created_at.to_i,
          amr: ['pwd'],
          email: account.send(OIDCProvider.account_email),
          email_verified: true,
          given_name: account.send(OIDCProvider.account_given_name),
          family_name: account.send(OIDCProvider.account_family_name),
        )
      else
        OpenIDConnect::ResponseObject::IdToken.new(
          iss: OIDCProvider.issuer,
          sub: account.send(OIDCProvider.account_identifier),
          aud: authorization.client_id,
          nonce: nonce,
          exp: expires_at.to_i,
          iat: created_at.to_i,
          auth_time:created_at.to_i,
          amr: ['pwd']
        )
      end
    end

    def to_jwt
      to_response_object.to_jwt(self.class.private_jwk)
    end

    private

    class << self
      def config
        {
          issuer: OIDCProvider.issuer,
          jwk_set: JSON::JWK::Set.new(public_jwk)
        }
      end

      def oidc_provider_key_path
        ENV.fetch('OIDC_PROVIDER_PRIVATE_KEY_PATH', Rails.root.join('lib/oidc_provider_key.pem'))
      end

      def key_pair
        @key_pair ||= OpenSSL::PKey::RSA.new(File.read(oidc_provider_key_path), ENV[PASSPHRASE_ENV_VAR])
      end

      def private_jwk
        JSON::JWK.new key_pair
      end

      def public_jwk
        JSON::JWK.new key_pair.public_key, {use: 'sig',alg: 'RS256'}
      end
    end
  end
end
