# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Server) do
  it 'fails to load if the access_token_validation_type is not recognized' do
    expect do
      Rails.application.config.with(access_token_validation_type: :unknown) do
        validation_application_config_via_initializer!
      end
    end.to(raise_error(/Unexpected option/))
  end

  it 'fails to load if the registration_type is not recognized' do
    expect do
      Rails.application.config.with(registration_type: 'do-it-yourself') do
        validation_application_config_via_initializer!
      end
    end.to(raise_error(/Unexpected option/))
  end
end
