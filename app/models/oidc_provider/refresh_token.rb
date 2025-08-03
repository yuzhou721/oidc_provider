# frozen_string_literal: true

module OIDCProvider
  class RefreshToken < ApplicationRecord
    scope :valid, -> { where(arel_table[:expires_at].gteq(Time.now.utc)) }
    attribute :token, :string, default: -> { SecureRandom.hex 32 }
    attribute :expires_at, :datetime, default: -> { 1.month.from_now }
    attribute :revoked_at, :datetime
    serialize :scopes, coder: JSON
  end
end
