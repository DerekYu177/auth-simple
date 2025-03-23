# a stand-in for db state
module Utilities
  module Storage
    module Storable
      include ActiveSupport::Concern

      def clear!
        @storage = {}        
      end

      def method_missing(method, *args, **kwargs)
        attribute = method.to_s.delete_suffix('=').to_sym

        return super unless respond_to_missing?(attribute)

        if method.to_s.ends_with?('=')
          @storage.send(:[]=, attribute, *args, **kwargs)
        else
          @storage.send(:[], attribute, *args, **kwargs)
        end
      end

      def respond_to_missing?(method)
        storable_attributes.include?(method)
      end

      def storable_attributes = []
    end

    class ResourceServer
      include Singleton
      include Storable

      ID = '1'

      def client_id = ID

      def initialize
        @storage = {}
      end

      def storable_attributes
        %i[
          current_access_token
          current_user
          code_verifier
        ]
      end
    end

    # data shared between resource server & authorization server
    class ClientRegistration
      include Singleton

      def id = ResourceServer::ID
      def callback_url(...) = url_helpers.admin_callback_path(...)

      private

      def url_helpers
        Rails.application.routes.url_helpers
      end
    end

    class AuthorizationServer
      include Singleton
      include Storable

      def initialize
        @storage = {}
      end

      def storable_attributes
        %i[
          authorization_code_grants
          access_tokens
        ]
      end
    end
  end
end
