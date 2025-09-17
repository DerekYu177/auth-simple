# frozen_string_literal: true

module Utilities
  class API
    Response = Struct.new(:status, :body, :headers, keyword_init: true)

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

        status, headers, response = Rails.application.call(requestenv)

        Response.new(status:, headers:, body: response.first) 
      end
    end
  end
end
