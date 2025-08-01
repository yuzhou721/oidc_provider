require 'openid_connect/response_object/user_info/user_info_with_nonce'
module OIDCProvider
  class AccountToUserInfo
    def call(account, scope_names, nonce)
      scopes = scope_names.map { |name| OIDCProvider.supported_scopes.detect { |scope| scope.name == name } }.compact
      OpenIDConnect::ResponseObject::UserInfoWithNonce.new({sub: account.send(OIDCProvider.account_identifier), nonce: nonce}).tap do |user_info|
        scopes.each do |scope|
          UserInfoBuilder.new(user_info, account).run(&scope.work)
        end
      end
    end
  end
end