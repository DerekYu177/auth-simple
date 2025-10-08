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

      # ensure that subject doesn't break the flow
      # if an error occurs
      JSON.parse(last_response.body.presence || "{}")
    end
  end

  include_context 'fetches access token'

  it 'valid attributes' do
    response = subject

    expect(response).to(include('access_token'))
    expect(response).to(include('token_type'))
  end

  context 'when using reference tokens', access_token_validation_type: 'reference' do
    shared_examples 'has correct format when introspected' do
      it do
        response = subject

        expect(response['access_token']).to(include('access-token:'))
        opaque_access_token = response['access_token']

        # introspect the access token manually to ensure that the attributes are correct
        access_token = ::OAuth::AccessToken.introspect(opaque_access_token)

        expect(access_token['active']).to(be_truthy)
        expect(access_token['username']).to(eq('DerekYu177'))
        expect(access_token['aud']).to(eq('https://auth-ser.derekyu.com'))
      end
    end

    context 'when using static registration', registration_type: 'static' do
      it_behaves_like 'has correct format when introspected'
    end

    context 'when using dynamic registration', registration_type: 'dynamic' do
      before do
        # force dynamic registration
        get('/admin')
      end

      it_behaves_like 'has correct format when introspected'
    end
  end

  context 'when using self-encoded tokens', access_token_validation_type: 'self-encoded' do
    shared_examples 'has correct format when JWT introspected' do
      it do
        response = subject

        payload = OAuth::JWT.introspect(response['access_token'])

        expect(payload['username']).to(eq('DerekYu177'))
        expect(payload['client_id']).to(eq(ResourceServer::Storage::ID))
        expect(payload['aud']).to(eq('https://auth-ser.derekyu.com'))
      end
    end

    context 'when using static registration', registration_type: 'static' do
      it_behaves_like 'has correct format when JWT introspected'
    end

    context 'when using dynamic registration', registration_type: 'dynamic' do
      before do
        # force dynamic registration
        get('/admin')
      end

      it_behaves_like 'has correct format when JWT introspected'
    end
  end

  context 'when registration type is static but ClientRegistration is empty', registration_type: 'static' do
    before do
      ClientRegistration.instance.clear!
    end

    it 'returns unrecognized' do
      subject # has valid params

      query = parse_redirect(last_response)

      expect(query).to(include('error'))
      expect(query).to(include('error_description'))

      expect(query["error"]).to(eq('invalid_request'))
      expect(query["error_description"]).to(eq('unrecognized client 1'))
    end
  end

  context 'when client has not registered', registration_type: 'dynamic' do
    it 'returns unrecognized' do
      subject # has valid params

      query = parse_redirect(last_response)

      expect(query).to(include('error'))
      expect(query).to(include('error_description'))

      expect(query["error"]).to(eq('invalid_request'))
      expect(query["error_description"]).to(eq('unrecognized client 1'))
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
