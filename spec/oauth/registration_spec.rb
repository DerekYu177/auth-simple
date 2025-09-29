# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('OAuth registration') do
  describe 'when registration_type=dynamic', registration_type: 'dynamic' do
    context 'when no registration has been made' do
      before do
        ClientRegistration.instance.clear!
      end

      it 'calls to oauth/authorize will fail' do
        get(
          '/oauth/authorize',
          **authorization_params,
        )

        query = parse_redirect(last_response)

        expect(query['error_description']).to(eq('unrecognized client'))
      end

      it 'dyanmically registers when client tries to authorize' do
        # TODO
        get '/admin'
      end
    end
  end

  describe 'when registration_type=static', registration_type: 'static' do
  end

  def authorization_params(**params)
    {
      client_id: ResourceServer::Storage::ID,
      code_challenge: 'random',
      code_challenge_method: 'S256',
      authenticated: 1,
      response_type: 'code',
      **params,
    }
  end
end
