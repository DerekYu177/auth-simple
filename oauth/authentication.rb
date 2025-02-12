# frozen_string_literal: true

module OAuth
  class Authenticate
    class << self
      def start!(...)
        new(...).authenticate!
      end
    end

    attr_reader :request, :redirect_to, :current_user

    def initialize(request:, redirect_to:, current_user:)
      @request = request
      @redirect_to = redirect_to
      @current_user = current_user
    end

    def authenticate!
      # check first if the bearer access token exists
      # if it is, perform introspection (?)
      # if it isn't, redirect to oauth/authorize, get the grant
      # exchange the grant for an access token
      # place the access token into the header
      # perform introspection (?)

      return if current_user.present?

      code_challenge = 'random'
      code_challenge_method = 'S256'

      # this will pass, because we have authenticated=1
      # will redirect to the callback
      # which will then perform the grant<->token exchange
      helper = Rails.application.routes.url_helpers
      helper.oauth_authorize_path(
        client_id: 1,
        code_challenge:,
        code_challenge_method:,
        authenticated: 1,
        response_type: 'code',
        redirect_to:,
        state: PseudoState.new.to_s
      )
    end
  end
end
