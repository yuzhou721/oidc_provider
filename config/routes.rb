OIDCProvider::Engine.routes.draw do
  resource :authorizations, only: [:new, :create]

  resource :user_info, only: :show
  get 'sessions/logout', to: 'sessions#destroy', as: :end_session

  post 'tokens', to: proc { |env| OIDCProvider::TokenEndpoint.new.call(env) }
  get 'jwks.json', as: :jwks, to: proc { |env| [200, {'Content-Type' => 'application/json'}, [OIDCProvider::IdToken.config[:jwk_set].as_json.to_json]] }
end
