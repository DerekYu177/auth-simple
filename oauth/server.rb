# frozen_string_literal: true

# uncommenting this line requires adding a database
# require 'rails/all'
require 'action_controller/railtie'

# TODO make all optional / configurations part of a plugins YAML file

class Server < Rails::Application
  config.load_defaults Rails::VERSION::STRING.to_f
  config.root = '__dir__'
  config.secret_key_base = 'secret'
  config.action_controller.default_url_options = { host: 'localhost' }
  config.eager_load = false
  config.logger = Logger.new($stdout)

  # application configurations
  config.access_token_validation_type = 'reference' # can be either 'reference' or 'self-encoded'
end

Rails.application.initialize!
Rails.application.routes.default_url_options = { host: 'localhost' }
Rails.application.routes.draw do
  get 'oauth/authorize' => 'authorization_server/oauth/authorization#new'
  post 'oauth/tokens' => 'authorization_server/oauth/tokens#create'

  if Rails.application.config.access_token_validation_type == 'reference'
    post 'oauth/introspect' => 'authorization_server/oauth/introspection#create'
  end

  get 'admin' => 'resource_server/authenticated#new'
  get 'admin/callback' => 'resource_server/callback#new'
end

ActiveSupport::Inflector.inflections(:en) do |inflect|
  inflect.acronym('OAuth')
  inflect.acronym('PKCE')
end

require_relative '../utilities/storage'
require_relative '../utilities/api'

PseudoState = Struct.new do
  def state = 'pseudo-state'
  def to_s = state
end

# data shared between resource server & authorization server
class ClientRegistration
  include Singleton

  def id = '1'
  def callback_url(...) = url_helpers.admin_callback_path(...)

  private

  def url_helpers
    Rails.application.routes.url_helpers
  end
end

# TODO This file is meant to demonstrate OAuth 2.1. The main differences are as follows:
#   PKCE is required for all OAuth clients using the authorization code flow
#   Redirect URIs must be compared using exact string matching
#   The Implicit grant (response_type=token) is omitted from this specification
#   The Resource Owner Password Credentials grant is omitted from this specification
#   Bearer token usage omits the use of bearer tokens in the query string of URIs
#   Refresh tokens for public clients must either be sender-constrained or one-time use
# For each of the above, a specific comment must be made and the changes explicitly made

module ResourceServer
  # TODO use the state param
  # TODO have unauthenticated routes to test

  class Storage < Utilities::Storage::Base
    self.storable_attributes = %i(current_access_token current_user code_verifier)
    ID = '1'
    def client_id = ID
  end

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

      # OAuth 2.1 Major Difference #1:
      # PKCE is required for all OAuth clients using the authorization code flow
      code_verifier = ::OAuth::PKCE.generate_code_verifier
      code_challenge = ::OAuth::PKCE.generate_code_challenge(code_verifier)
      code_challenge_method = ::OAuth::PKCE::SUPPORTED_CODE_CHALLENGE_VERSION

      cache.code_verifier = code_verifier

      redirect_to oauth_authorize_path(
        client_id: cache.client_id,
        code_challenge:,
        code_challenge_method:,
        authenticated: 1,
        response_type: 'code',
        redirect_to: '', # ?
        state: PseudoState.new.to_s
      )
    end

    def current_user
      cache.current_access_token
    end

    def cache
      @cache ||= ResourceServer::Storage.instance
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
    def new
      raise 'expected grant, did not receive' unless callback_params[:code]

      # OAuth 2.1 Section 1.2 Protocol Flow (3)
      # The client requests an access token by authenticating
      # with the authorization server and presenting the authorization grant.
      response = Utilities::API.post(
        '/oauth/tokens',
        body: {
          'grant_type' => 'authorization_code',
          'code_verifier' => cache.code_verifier,
          'code' => callback_params[:code],
          'client_id' => cache.client_id
        }
      )
      tokens = JSON.parse(response.body)

      access_token = tokens['access_token']

      cache.current_access_token = access_token

      introspect = introspect_access_token(access_token)
      cache.current_user = introspect['username']

      redirect_to(admin_path)
    end

    private

    def introspect_access_token(access_token)
      case Rails.application.config.access_token_validation_type
      when 'reference'
        ::OAuth::AccessToken.introspect(access_token)
      when 'self-encoded'
        ::OAuth::JWT.introspect(access_token)
      end
    end

    def cache
      @cache ||= ResourceServer::Storage.instance
    end

    def callback_params
      params.permit(:code, :state)
    end
  end
end

module AuthorizationServer
  # TODO remove params[:authentication] == 1 and replace with a redirected route that "authenticates"
  # TODO Have static registration and dynamic registration plugins

  class Storage < Utilities::Storage::Base
    def self.storable_attributes = %i(authorization_code_grants access_tokens)
  end

  module OAuth
    class AuthorizationController < ActionController::Base
      include Rails.application.routes.url_helpers

      before_action :validate_request!, only: :new

      def new
        # requires authentication here
        # returns authorization grant

        # we MUST associate the code_challenge
        # and code_challenge_method with the issued authorization_code
        # we'll store the trifecta (cc, ccm, code)
        # in our shared state object
        code = "authorization-code-grant:#{SecureRandom.hex(10)}"

        cache.authorization_code_grants ||= {}
        cache.authorization_code_grants[code] = {
          code_challenge: authorization_params[:code_challenge],
          code_challenge_method: authorization_params[:code_challenge_method]
        }

        case authorization_params[:client_id]
        when client_registration.id
          redirect_to client_registration.callback_url(code:, state: authorization_params[:state])
        else
          oauth_error!('unrecognized client')
        end
      end

      private

      def cache
        @cache ||= AuthorizationServer::Storage.instance
      end

      def client_registration
        @client_registration ||= ClientRegistration.instance
      end

      def validate_request!
        return oauth_error!('response_type') unless authorization_params[:response_type] == 'code'
        return oauth_error!('client_id') unless authorization_params[:client_id]
        return oauth_error!('code_challenge') unless authorization_params[:code_challenge]
        return oauth_error!('code_challenge_method') unless ::OAuth::PKCE.supported?(authorization_params[:code_challenge_method])
        return oauth_error!('invalid authentication') unless params[:authenticated] == '1'

        nil
      end

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
          if valid_grant? && valid_client? && valid_code_verifier?
            render(
              json: {
                access_token: access_token(
                  username: 'DerekYu177',
                  client_id: token_params[:client_id]
                ),
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

      def access_token(...)
        case Rails.application.config.access_token_validation_type
        when 'reference'
          ::OAuth::AccessToken.build(...)
        when 'self-encoded'
          ::OAuth::JWT.build(...)
        end
      end

      def valid_grant?
        # there's no super easy way to validate other than by introspecting it
        cache.authorization_code_grants[token_params[:code]].present?
      end

      def valid_client?
        token_params[:client_id] == ClientRegistration.instance.id
      end

      def valid_code_verifier?
        challenge = cache.authorization_code_grants[token_params[:code]]

        return false unless ::OAuth::PKCE.supported?(challenge[:code_challenge_method])
        return false unless token_params[:code_verifier]

        ::OAuth::PKCE.valid_code_challenge?(
          stored_challenge: challenge[:code_challenge],
          provided_verifier: token_params[:code_verifier],
        )
      end

      def cache
        @cache ||= AuthorizationServer::Storage.instance
      end

      def token_params
        params.permit(*PERMITTED_PARAMS)
      end

      PERMITTED_PARAMS = %i[
        grant_type
        client_id
        code
        code_verifier
      ].freeze

      def oauth_error!(error_description, message: 'invalid_request')
        redirect_to(admin_path(error: message, error_description:, **token_params))
      end
    end
  end
end

require_relative 'token_introspection'
require_relative 'jwt'
require_relative 'pkce'
