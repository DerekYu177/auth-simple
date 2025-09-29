# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('oauth/authorize') do
  it 'succeeds' do
    get(
      '/oauth/authorize',
      client_id: ResourceServer::Storage::ID,
      code_challenge: 'random',
      code_challenge_method: 'S256',
      authenticated: 1,
      response_type: 'code'
    )
    query = parse_redirect(last_response)

    expect(query).to(include('code'))
    expect(query['code']).to(include('authorization-code-grant'))

    expect(last_response).to(redirect_to('/admin/callback'))
  end

  it 'when receives error will redirect' do
    get(
      '/oauth/authorize',
      client_id: ResourceServer::Storage::ID,
      code_challenge: 'random',
      code_challenge_method: 'S256',
      authenticated: 2,
      response_type: 'code'
    )
    query = parse_redirect(last_response)

    expect(query).to(include('error'))
    expect(query).to(include('error_description'))
  end
end
