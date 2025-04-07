# a stand-in for db state
module Utilities
  module Storage
    class Base
      include Singleton

      class_attribute :storable_attributes

      def clear!
        @storage = {}        
      end

      def initialize
        raise 'storage required!' unless self.class.storable_attributes
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
        self.class.storable_attributes.include?(method)
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

    class AuthorizationServer < Base
      def self.storable_attributes
        %i[
          authorization_code_grants
          access_tokens
        ]
      end
    end
  end
end
