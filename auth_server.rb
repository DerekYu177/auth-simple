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
        when '1'
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

    class TokensController < ActionController::Base
      skip_before_action :verify_authenticity_token

      def create
        case token_params[:grant_type]
        when 'authorization_code'
          # heh.
          if token_params[:code] == 'valid-grant'
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

module ResourceServer
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
        client_id: 1,
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

  class CallbackController < ActionController::Base
    mattr_accessor :access_token

    def new
      # we have a grant, now we have to exchange it
      # for an access token

      response = post_oauth_tokens!
      tokens = JSON.parse(response.body)

      # well, we don't have a storage mechanism
      # so I'll have to store it as a class variable. Haha.
      self.class.access_token = tokens['access_token']

      redirect_to(admin_path)
    end

    private

    def post_oauth_tokens!
      # looks like API requests are _not_ easily supported
      # as it conflicts with internal Shopify tool

      postenv = {
        'REQUEST_METHOD' => 'POST',
        'SERVER_NAME' => 'localhost',
        'SERVER_PORT' => '80',
        'SERVER_PROTOCOL' => 'HTTP/1.0',
        'QUERY_STRING' => '',
        'PATH_INFO' => '/oauth/tokens',
        'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        'CONTENT_LENGTH' => '58',
        'SCRIPT_NAME' => '',
        'REMOTE_ADDR' => '127.0.0.1',
        'HTTP_HOST' => 'localhost',
        'ORIGINAL_FULLPATH' => '/oauth/tokens',
        'ORIGINAL_SCRIPT_NAME' => '',
        'action_dispatch.request.request_parameters' => {
          'grant_type' => 'authorization_code',
          'code' => callback_params[:code],
          'client_id' => '1'
        }
      }

      _, _, response = Rails.application.call(postenv)
      response
    end

    def callback_params
      params.permit(:code, :state)
    end
  end
end
