# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('oauth/tokens') do
  shared_context 'fetches access token' do
    let(:code_verifier) { "code-verifier:#{SecureRandom.hex(10)}" }
    let(:access_grant) { 'authorization-code-grant' }

    before do
      # pre-populate the "database"
      cache = AuthorizationServer::Storage.instance
      cache.authorization_code_grants = {}
      cache.authorization_code_grants[access_grant] = {
        code_challenge_method: 'S256',
        code_challenge: Base64.urlsafe_encode64(Digest::SHA2.hexdigest(code_verifier))
      }
    end

    subject do
      post(
        '/oauth/tokens',
        grant_type: 'authorization_code',
        code_verifier: code_verifier,
        code: access_grant,
        client_id: ResourceServer::Storage::ID
      )

      JSON.parse(last_response.body)
    end
  end

  context 'returns valid response' do
    include_context 'fetches access token'

    it 'valid attributes' do
      response = subject

      expect(response).to(include('access_token'))
      expect(response).to(include('token_type'))
    end

    it 'when using reference tokens', access_token_validation_type: 'reference' do
      response = subject

      expect(response['access_token']).to(include('access-token:'))
      opaque_access_token = response['access_token']

      # introspect the access token manually to ensure that the attributes are correct
      access_token = ::OAuth::AccessToken.introspect(opaque_access_token)

      expect(access_token['active']).to(be_truthy)
      expect(access_token['username']).to(eq('DerekYu177'))
      expect(access_token['aud']).to(eq('https://auth-ser.derekyu.com'))
    end

    it 'when using self-encoded tokens', access_token_validation_type: 'self-encoded' do
      response = subject

      payload = OAuth::JWT.introspect(response['access_token'])

      expect(payload['username']).to(eq('DerekYu177'))
      expect(payload['client_id']).to(eq(ResourceServer::Storage::ID))
      expect(payload['aud']).to(eq('https://auth-ser.derekyu.com'))
    end
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
