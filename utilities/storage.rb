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
  end
end
