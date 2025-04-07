# frozen_string_literal: true

require 'rails/all'

module OAuth
  class AccessToken
    class << self
      def build(user_attributes)
        access_token = "access-token:#{SecureRandom.hex(10)}"

        cache = AuthorizationServer::Storage.instance
        cache.access_tokens ||= {}
        cache.access_tokens[access_token] = user_attributes

        access_token
      end

      def introspect(access_token)
        # make a call to the introspection endpoint
        response = Utilities::API.post(
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
        return render(json: { active: false }) unless valid_token?

        render(
          json: {
            active: true,
            **cache.access_tokens[introspection_params[:token]]
          }
        )
      end

      private

      def valid_token?
        cache.access_tokens ||= {}
        cache.access_tokens.key?(introspection_params[:token])
      end

      def cache
        @cache ||= AuthorizationServer::Storage.instance
      end

      def introspection_params
        params.permit(:token)
      end
    end
  end
end
