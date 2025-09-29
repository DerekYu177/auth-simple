# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('oauth/tokens') do
  it 'returns an access token' do
    # pre-populate the "database"

    code_verifier = "code-verifier:#{SecureRandom.hex(10)}"
    grant = 'authorization-code-grant'

    cache = AuthorizationServer::Storage.instance
    cache.authorization_code_grants = {}
    cache.authorization_code_grants[grant] = {
      code_challenge_method: 'S256',
      code_challenge: Base64.urlsafe_encode64(Digest::SHA2.hexdigest(code_verifier))
    }

    post(
      '/oauth/tokens',
      grant_type: 'authorization_code',
      code_verifier: code_verifier,
      code: grant,
      client_id: ResourceServer::Storage::ID
    )

    response = JSON.parse(last_response.body)

    expect(response).to(include('access_token'))
    expect(response).to(include('token_type'))
  end

  it 'when using reference tokens', access_token_validation_type: 'reference' do
    code_verifier = "code-verifier:#{SecureRandom.hex(10)}"
    grant = 'authorization-code-grant'

    cache = AuthorizationServer::Storage.instance
    cache.authorization_code_grants = {}
    cache.authorization_code_grants[grant] = {
      code_challenge_method: 'S256',
      code_challenge: Base64.urlsafe_encode64(Digest::SHA2.hexdigest(code_verifier))
    }

    post(
      '/oauth/tokens',
      grant_type: 'authorization_code',
      code_verifier: code_verifier,
      code: grant,
      client_id: ResourceServer::Storage::ID
    )

    response = JSON.parse(last_response.body)

    expect(response['access_token']).to(include('access-token:'))
  end

  it 'when using self-encoded tokens', access_token_validation_type: 'self-encoded' do
    code_verifier = "code-verifier:#{SecureRandom.hex(10)}"
    grant = 'authorization-code-grant'

    cache = AuthorizationServer::Storage.instance
    cache.authorization_code_grants = {}
    cache.authorization_code_grants[grant] = {
      code_challenge_method: 'S256',
      code_challenge: Base64.urlsafe_encode64(Digest::SHA2.hexdigest(code_verifier))
    }

    post(
      '/oauth/tokens',
      grant_type: 'authorization_code',
      code_verifier: code_verifier,
      code: grant,
      client_id: ResourceServer::Storage::ID
    )

    response = JSON.parse(last_response.body)

    payload = OAuth::JWT.introspect(response['access_token'])

    expect(payload['username']).to(eq('DerekYu177'))
    expect(payload['client_id']).to(eq(ResourceServer::Storage::ID))
  end

  it 'returns unrecognized when token grant-type is unrecognized' do
    post(
      '/oauth/tokens',
      grant_type: 'unsupported'
    )

    query = parse_redirect(last_response)

    expect(query).to(include('error'))
    expect(query).to(include('error_description'))

    expect(query["error"]).to(eq('unsupported_grant_type'))
  end
end
