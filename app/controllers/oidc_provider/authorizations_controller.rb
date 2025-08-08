# frozen_string_literal: true

module OIDCProvider
  class AuthorizationsController < ApplicationController
    include Concerns::ConnectEndpoint

    skip_before_action :verify_authenticity_token

    before_action :require_oauth_request
    before_action :require_response_type_code
    before_action :require_client
    before_action :reset_login_if_necessary
    before_action :require_authentication

    def create
      Rails.logger.info "scopes: #{requested_scopes}"

      authorization = build_authorization_with(requested_scopes)

      oauth_response.code = authorization.code if @requested_type==:code or  @requested_type == :hybrid
      oauth_response.id_token = authorization.id_token.to_jwt if @requested_type==:id_token or  @requested_type == :hybrid
      oauth_response.redirect_uri = @redirect_uri
      oauth_response.approve!
      redirect_to oauth_response.location,allow_other_host: true
    end

    private

    def build_authorization_with(scopes)
      Authorization.create(
        client_id: @client.identifier,
        nonce: oauth_request.nonce,
        scopes: scopes,
        account: oidc_current_account,
        issuer: request.base_url
      )
    end

    def require_client
      @client = ClientStore.new.find_by(identifier: oauth_request.client_id) or oauth_request.invalid_request! 'not a valid client'
      @redirect_uri = oauth_request.verify_redirect_uri! @client.redirect_uri
    end

    def requested_scopes
      @requested_scopes ||= (['openid'] + OIDCProvider.supported_scopes.map(&:name)) & oauth_request.scope
    end
    helper_method :requested_scopes

    def require_response_type_code
      type =  oauth_request.response_type
      type.nil? && oauth_request.unsupported_response_type!
      case type
      when :code
        @requested_type=:code
      when :id_token
        @requested_type=:id_token
      when ->(ary) do ary.include?(:code) && ary.include?(:id_token) end
        @requested_type=:hybrid
        # when type.include?("token")
        #   @response_type=:token
      else
        oauth_request.unsupported_response_type!
      end


    end

    def reset_login_if_necessary
      if params[:prompt] == "login"
        # A `prompt=login` param means that we must prompt the user for sign in.
        # So we will forcibly sign out the user here and then redirect them so they
        # don't get redirected back to the url that contains `prompt=login`
        unauthenticate!
        redirect_to url_for(request.query_parameters.except(:prompt)), allow_other_host: true
      end
    end
  end
end
