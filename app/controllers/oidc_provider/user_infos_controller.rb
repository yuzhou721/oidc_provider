module OIDCProvider
  class UserInfosController < ApplicationController
    before_action :require_access_token

    def show

      render json: AccountToUserInfo.new.(current_token.authorization.account, current_token.authorization.scopes, current_token.authorization.nonce)
    end
  end
end