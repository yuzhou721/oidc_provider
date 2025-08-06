# frozen_string_literal: true

require "openid_connect"
require "oidc_provider/engine"

module OIDCProvider

  module Scopes
    OpenID = "openid"
    Profile = "profile"
    Email = "email"
    Address = "address"
    Phone = "phone"
    OfflineAccess = "offline_access"
  end

  autoload :TokenEndpoint, 'oidc_provider/token_endpoint'
  autoload :ClientStore, 'oidc_provider/client_store'
  autoload :Client, 'oidc_provider/client'
  autoload :AccountToUserInfo, 'oidc_provider/account_to_user_info'
  autoload :Scope, 'oidc_provider/scope'
  autoload :UserInfoBuilder, 'oidc_provider/user_info_builder'

  mattr_accessor :issuer

  mattr_accessor :supported_scopes
  @@supported_scopes = []

  mattr_accessor :clients
  @@clients = []

  mattr_accessor :account_class
  @@account_class = "User"

  mattr_accessor :current_account_method
  @@current_account_method = :current_user

  mattr_accessor :current_authentication_method
  @@current_authentication_method = :authenticate_user!

  mattr_accessor :current_unauthenticate_method
  @@current_unauthenticate_method = :sign_out

  mattr_accessor :account_identifier
  @@account_identifier = :id

  mattr_accessor :account_email
  @@account_identifier = :email

  mattr_accessor :account_given_name
  @@account_identifier = :given_name

  mattr_accessor :account_family_name
  @@account_identifier = :family_name

  # Include User claims from scopes in the id_token, for applications that don't access the userinfo endpoint.
  mattr_accessor :include_user_claims_in_id_token
  @@include_user_claims_in_id_token = false

  mattr_accessor :after_sign_out_path

  def self.add_client(&block)
    @@clients << Client::Builder.new(&block).build
  end

  def self.add_scope(name, &block)
    @@supported_scopes << Scope.new(name, &block)
  end

  def self.configure
    yield self
  end
end
