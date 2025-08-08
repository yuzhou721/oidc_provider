class AddIssuerToOIDCProviderAuthorizations < ActiveRecord::Migration[5.1]
  def change
    add_column :oidc_provider_authorizations, :issuer, :string
  end

end
