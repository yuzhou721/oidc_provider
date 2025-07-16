# frozen_string_literal: true

class CreateOIDCProviderRefreshTokens < ActiveRecord::Migration[5.1]
  def change
    create_table :oidc_provider_refresh_tokens do |t|
      t.string :client_id, null: false

      t.string :token, null: false
      t.datetime :expires_at, null: false
      t.datetime :revoked_at
      t.text :scopes, null: false

      t.timestamps
    end
  end
end