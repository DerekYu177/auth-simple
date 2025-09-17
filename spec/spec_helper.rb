# frozen_string_literal: true

require 'debug'
require_relative '../oauth/server'

RSpec.configure do |config|
  config.around do |example|
    if (app_options = example.metadata.slice(:access_token_validation_type))
      Rails.application.config.with(**app_options) { example.call }
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
