# frozen_string_literal: true

module Utilities
  class API
    class << self
      def post(path, body:)
        # looks like API requests are _not_ easily supported
        # as it conflicts with internal Shopify tool

        requestenv = {
          'REQUEST_METHOD' => 'POST',
          'PATH_INFO' => path,
          'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
          'HTTP_HOST' => 'localhost',
          'action_dispatch.request.request_parameters' => body
        }

        _, _, response = Rails.application.call(requestenv)

        response
      end
    end
  end
end
