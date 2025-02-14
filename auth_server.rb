# frozen_string_literal: true

require 'rails/all'
require 'action_controller/railtie'

class AuthServer < Rails::Application
  config.load_defaults Rails::VERSION::STRING.to_f
  config.root = '__dir__'
  config.secret_key_base = 'secret'
  config.action_controller.default_url_options = { host: 'localhost' }
  config.eager_load = false
  config.logger = Logger.new($stdout)
end

Rails.application.initialize!
Rails.application.routes.default_url_options = { host: 'localhost' }
Rails.application.routes.draw do
  get 'oauth/authorize' => 'authorization_server/oauth/authorization#new'
  post 'oauth/tokens' => 'authorization_server/oauth/tokens#create'

  get 'admin' => 'resource_server/authenticated#new'
  get 'admin/callback' => 'resource_server/callback#new'
end

# we don't have a database, clearly.
# but these are necessary configuration
database = 'development.sqlite3'
ENV['DATABASE_URL'] = "sqlite3:#{database}"
ActiveRecord::Base.establish_connection(adapter: 'sqlite3', database: database)
ActiveRecord::Schema.define {}

ActiveSupport::Inflector.inflections(:en) do |inflect|
  inflect.acronym('OAuth')
end

PseudoState = Struct.new do
  def state = 'pseudo-state'
  def to_s = state
end

module ResourceServer
  CLIENT_ID = '1'

  # OAuth 2.1 Section 1.2 Protocol Flow (1)
  # The client requests authorization from the resource owner.
  # The authorization request can be made directly to the resource owner,
  # or preferably indirectly via the authorization server as an intermediary.
  class AuthenticatedController < ActionController::Base
    before_action :require_authentication, only: :new

    def new
      render(json: { result: :authenticated })
    end

    def index; end

    private

    def require_authentication
      return if current_user.present?

      redirect_to oauth_authorize_path(
        client_id: CLIENT_ID,
        code_challenge: 'random',
        code_challenge_method: 'S256',
        authenticated: 1,
        response_type: 'code',
        redirect_to: '', # ?
        state: PseudoState.new.to_s
      )
    end

    def current_user
      ResourceServer::CallbackController.access_token
    end
  end

  # OAuth 2.1 Section 1.2 Protocol Flow (2)
  # The client receives an authorization grant,
  # which is a credential representing the resource owner's authorization,
  # expressed using one of the authorization grant types
  # defined in this specification or using an extension grant type.
  # The authorization grant type depends on the method used by the
  # client to request authorization and the types
  # supported by the authorization server.
  class CallbackController < ActionController::Base
    mattr_accessor :access_token

    def new
      raise 'expected grant, did not receive' unless callback_params[:code]

      # OAuth 2.1 Section 1.2 Protocol Flow (3)
      # The client requests an access token by authenticating
      # with the authorization server and presenting the authorization grant.
      response = post_oauth_tokens!(
        body: {
          'grant_type' => 'authorization_code',
          'code' => callback_params[:code],
          'client_id' => CLIENT_ID
        }
      )
      tokens = JSON.parse(response.body)

      # well, we don't have a storage mechanism
      # so I'll have to store it as a class variable. Haha.
      self.class.access_token = tokens['access_token']

      redirect_to(admin_path)
    end

    private

    def post_oauth_tokens!(body:)
      # looks like API requests are _not_ easily supported
      # as it conflicts with internal Shopify tool

      postenv = {
        'REQUEST_METHOD' => 'POST',
        'PATH_INFO' => '/oauth/tokens',
        'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        'HTTP_HOST' => 'localhost',
        'action_dispatch.request.request_parameters' => body
      }

      _, _, response = Rails.application.call(postenv)
      response
    end

    def callback_params
      params.permit(:code, :state)
    end
  end
end

module AuthorizationServer
  module OAuth
    class AuthorizationController < ActionController::Base
      include Rails.application.routes.url_helpers

      def new
        # requires authentication here
        # returns authorization grant
        return oauth_error!('invalid response_type') unless authorization_params[:response_type] == 'code'
        return oauth_error!('unauthorized_client') unless authorization_params[:client_id]
        return oauth_error!('missing code_challenge') unless authorization_params[:code_challenge]

        unless authorization_params[:code_challenge_method] == 'S256'
          return oauth_error!(
            'invalid code_challenge_method'
          )
        end
        return oauth_error!('invalid authentication') unless params[:authenticated] == '1'

        case authorization_params[:client_id]
        when ResourceServer::CLIENT_ID
          redirect_to admin_callback_path(code: 'valid-grant', state: authorization_params[:state])
        else
          oauth_error!('unrecognized client')
        end
      end

      private

      PERMITTED_PARAMS = %i[
        response_type
        client_id
        code_challenge
        code_challenge_method
        authenticated
        redirect_to
        state
      ].freeze

      def authorization_params
        params.permit(*PERMITTED_PARAMS)
      end

      def oauth_error!(error_description, message: 'invalid_request')
        redirect_to(admin_path(error: message, error_description:, **authorization_params.except(:authenticated)))
      end
    end

    # OAuth 2.1 Section 1.2 Protocol Flow (4)
    # The authorization server authenticates the client
    # and validates the authorization grant, and if valid, issues an access token.
    class TokensController < ActionController::Base
      skip_before_action :verify_authenticity_token

      def create
        case token_params[:grant_type]
        when 'authorization_code'
          # heh.
          if token_params[:code] == 'valid-grant' && token_params[:client_id] == ResourceServer::CLIENT_ID
            render(
              json: {
                access_token: 'valid-access-token',
                token_type: 'access-token',
                expires_in: 1.hour.to_i,
                refresh_token: nil
              }.compact
            )
          else
            oauth_error!('invalid code')
          end
          # something here?
        else
          oauth_error!("#{token_params[:grant_type]} unrecognized", message: 'unsupported_grant_type')
        end
      end

      private

      def token_params
        params.permit(:grant_type, :client_id, :code)
      end

      def oauth_error!(error_description, message: 'invalid_request')
        redirect_to(admin_path(error: message, error_description:, **token_params))
      end
    end
  end
end
