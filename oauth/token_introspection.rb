# frozen_string_literal: true

require 'rails/all'

module OAuth
  class AccessToken
    class << self
      def introspect(access_token)
        # make a call to the introspection endpoint
        response = API.post(
          '/oauth/introspect',
          body: { token: access_token }
        )

        JSON.parse(response.body)
      end
    end
  end
end

module AuthorizationServer
  module OAuth
    # Corresponds to OAuth 2.0 Token Introspection
    class IntrospectionController < ActionController::Base
      skip_before_action :verify_authenticity_token

      def create
        return render(json: { active: false }) unless introspection_params[:token] == State::AuthorizationServer::TOKEN

        render(
          json: {
            active: true,
            # scope
            client_id: State::ClientRegistration.instance.id,
            # exp,
            # iat,
            # sub,
            # iss
            username: 'DerekYu177'
          }
        )
      end

      private

      def introspection_params
        params.permit(:token)
      end
    end
  end
end
