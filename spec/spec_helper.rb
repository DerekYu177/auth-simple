# frozen_string_literal: true

require 'debug'
require_relative '../app/server'

RSpec.configure do |config|
  include Rack::Test::Methods

  def app = Rails.application

  config.before do
    ResourceServer::Storage.instance.clear!
    AuthorizationServer::Storage.instance.clear!
    ClientRegistration.instance.send(:reset!)

    def default_host = 'localhost'
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

def validation_application_config_via_initializer!
  Rails.application.initializers.select { |i| i.name.to_s.include?('application') }.each(&:run)
end

RSpec::Matchers.define('redirect_to') do |expected|
  match do |actual|
    URI(actual.location).path == expected
  end

  failure_message do |actual|
    "expected redirect to #{expected}, but was to #{actual.location} instead"
  end
end

def parse_redirect(response)
  expect(response).to(be_redirect)
  redirect_to = response['location']

  uri = URI(redirect_to)
  Rack::Utils.parse_query(uri.query)
end
