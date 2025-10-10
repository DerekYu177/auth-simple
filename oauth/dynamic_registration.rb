# frozen_string_literal: true

module OAuth
  module DynamicRegistration
    extend ActiveSupport::Concern

    included do
      def dynamically_register
        Utilities::API.post(
          '/oauth/register',
          body: {
            redirect_uris: ['http://localhost/admin/callback'],
            client_name: 'Dynamically Registered Client',
            # TODO: jwks_uri
          },
        )
      end

      def dynamic_registration?
        Rails.application.config.registration_type == 'dynamic'
      end
    end
  end
end

module AuthorizationServer
  module OAuth
    class DynamicRegistrationController < ActionController::Base
      skip_before_action :verify_authenticity_token

      # TODO: require some sort of client credential
      # for now, do not require any

      def create
        # TODO, handle validity
        ClientRegistration.instance.set!(
          # this is presumed,
          id: "1",
 
          # TODO: support multiple
          callback_url: registration_params[:redirect_uris].first,
        )

        # TODO, return if not valid?
        head(:ok)
      end

      private

      def registration_params
        params.permit(:client_name, redirect_uris: [])
      end
    end
  end
end
