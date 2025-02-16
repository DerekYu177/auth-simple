# frozen_string_literal: true

require 'jwt'

module OAuth
  class JWT
    class << self
      def build(user_attributes)
        ::JWT.encode(user_attributes, nil, 'none')
      end

      def introspect(access_token)
        payload, _header = ::JWT.decode(access_token, nil, false)
        payload
      end
    end
  end
end
