# frozen_string_literal: true

module OIDCProvider
  class TokenEndpoint
    attr_accessor :app

    delegate :call, to: :app

    def initialize
      @app = Rack::OAuth2::Server::Token.new do |req, res|
        case req.grant_type
        when :authorization_code
          Rails.logger.info "Client ID: #{req.client_id}"
          Rails.logger.info "Client secret: #{req.client_secret}"
          Rails.logger.info "Redirect URI: #{req.redirect_uri}"

          client = find_valid_client_from(req) || req.invalid_client!

          Rails.logger.info 'Found a client!'
          Rails.logger.info 'Grant type was an authorization code. Correct!'
          authorization = Authorization.valid.where(client_id: client.identifier, code: req.code).first || req.invalid_grant!
          Rails.logger.info 'We found an authorization matching this code!'
          with_refresh_token = authorization.scopes.include?('offline_access')
          res.access_token = authorization.access_token.to_bearer_token(with_refresh_token)
          res.id_token = authorization.id_token.to_jwt if authorization.scopes.include?('openid')
        when :refresh_token
          Rails.logger.info 'Grant type was an refresh_token code. Correct!'
          refresh_token = RefreshToken.valid.where(token: req.refresh_token).first || req.invalid_grant!
          authorization = refresh_token.authorization
          authorization.refresh!
          res.access_token = authorization.access_token.to_bearer_token(true)
        else
          Rails.logger.info "Unsupported grant type: #{req.grant_type.inspect}"
          req.unsupported_grant_type!
        end
      end
    end

    private
    def find_valid_client_from(req)
      client = ClientStore.new.find_by(
        identifier: req.client_id,
        secret: req.client_secret
      )

      return nil unless client

      client.redirect_uri.include?(req.redirect_uri) ? client : nil
    end

  end
end
