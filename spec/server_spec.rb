# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Server, type: :request) do
  include Rack::Test::Methods

  before do
    ResourceServer::Storage.instance.clear!
    AuthorizationServer::Storage.instance.clear!
  end

  context 'full authorization flow' do
    shared_context 'succeeds' do
      it do
        get('/admin')

        database = ResourceServer::Storage.instance
        expect(database.current_user)

        expect(last_response).to redirect_to('/oauth/authorize')

        follow_redirect!

        expect(last_response).to(be_redirect)
        expect(last_response).to redirect_to('/admin/callback')

        follow_redirect!

        expect(last_response).to(be_redirect)
        expect(last_response).to redirect_to('/admin')

        follow_redirect!

        response = JSON.parse(last_response.body)
        expect(response['result']).to(eq('authenticated'))

        expect(database.current_access_token).to(be_present)
        expect(database.current_user).to(be_present)

        expect(database.current_user).to(eq('DerekYu177'))
      end
    end

    context 'with reference tokens', access_token_validation_type: 'reference' do
      it_behaves_like 'succeeds'
    end

    context 'with reference tokens', access_token_validation_type: 'self-encoded' do
      it_behaves_like 'succeeds'
    end
  end

  context 'oauth/authorize' do
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

  describe 'oauth/tokens' do
    it 'oauth/tokens returns an access token' do
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

    it 'oauth/tokens when using reference tokens', access_token_validation_type: 'reference' do
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

    it 'oauth/tokens when using self-encoded tokens', access_token_validation_type: 'self-encoded' do
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

  context 'oauth/introspection', access_token_validation_type: 'reference' do
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

  def default_host
    'localhost'
  end

  private

  def parse_redirect(response)
    expect(response).to(be_redirect)
    redirect_to = response['location']

    uri = URI(redirect_to)
    Rack::Utils.parse_query(uri.query)
  end

  def app
    Rails.application
  end
end
