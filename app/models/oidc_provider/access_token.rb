module OIDCProvider
  class AccessToken < ApplicationRecord
    belongs_to :authorization

    scope :valid, -> { where(arel_table[:expires_at].gteq(Time.now.utc)) }

    attribute :token, :string, default: -> { SecureRandom.hex 32 }
    attribute :expires_at, :datetime, default: -> { 1.hours.from_now } 

    def to_bearer_token(with_refresh_token)
      if with_refresh_token
        Rack::OAuth2::AccessToken::Bearer.new(
          access_token: token,
          expires_in: (expires_at - Time.now).to_i,
          refresh_token:  (get_refresh_token(authorization.client_id,authorization.scopes.to_s)||generate_refresh_token(authorization.client_id,authorization.scopes.to_s)).token
        )
      else
        Rack::OAuth2::AccessToken::Bearer.new(
          access_token: token,
          expires_in: (expires_at - Time.now).to_i
        )
      end
    end

    private
    def get_refresh_token(client_id,scopes)
      RefreshToken
        .valid
        .where(client_id: client_id, revoked_at: nil,scopes:scopes)
        .first
    end
    def generate_refresh_token(client_id,scopes)
      RefreshToken.create!(
        client_id: client_id,
        scopes: scopes
      )
    end

  end
end
