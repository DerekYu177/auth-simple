# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('oauth/introspection', access_token_validation_type: 'reference') do
  it 'returns active' do
    access_token = 'access-token'

    cache = AuthorizationServer::Storage.instance
    cache.access_tokens ||= {}
    cache.access_tokens[access_token] = { username: 'DerekYu177' }

    post(
      '/oauth/introspect',
      token: access_token
    )

    response = JSON.parse(last_response.body)

    expect(response).to(include('active'))
    expect(response['active']).to(be_truthy)

    expect(response['username']).to(eq('DerekYu177'))
  end

  it 'with invalid token' do 
    post(
      '/oauth/introspect',
      token: 'invalid'
    )

    response = JSON.parse(last_response.body)

    expect(response).to(include('active'))
    expect(response['active']).to(be_falsey)

    expect(response['username']).not_to(eq('DerekYu177'))
  end
end
