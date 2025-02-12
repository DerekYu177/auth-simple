# frozen_string_literal: true

module OAuth
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
