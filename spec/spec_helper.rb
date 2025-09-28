# frozen_string_literal: true

require 'debug'
require_relative '../oauth/server'

RSpec.configure do |config|
  def validation_application_config_via_initializer!
    Rails.application.initializers.select { |i| i.name.to_s.include?('application') }.each(&:run)
  end

  config.around do |example|
    oauth_configuration_options = %i(access_token_validation_type registration_type)

    if (app_options = example.metadata.slice(*oauth_configuration_options)).present?
      Rails.application.config.with(**app_options) do
        # rerun validations just in case
        validation_application_config_via_initializer!
        example.call
      end
    else
      example.call
    end
  end
end

RSpec::Matchers.define('redirect_to') do |expected|
  match do |actual|
    URI(last_response.location).path == expected
  end

  failure_message do |actual|
    "expected redirect to #{expected}, but was to #{actual.location} instead"
  end
end
