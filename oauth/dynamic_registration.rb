# frozen_string_literal: true

module OAuth
  module DynamicRegistration
    extend ActiveSupport::Concern

    included do
      def dynamically_register
        # TODO
      end

      def dynamic_registration?
        Rails.application.config.registration_type == 'dynamic'
      end
    end
  end
end
