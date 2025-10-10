# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('end to end flows', type: :request) do
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

    context 'with static registration', registration_type: 'static' do
      it_behaves_like 'succeeds'
    end

    context 'with dynamic registration', registration_type: 'dynamic' do
      it_behaves_like 'succeeds'
    end
  end

  context 'with self-encoded tokens', access_token_validation_type: 'self-encoded' do
    it_behaves_like 'succeeds'

    context 'with static registration', registration_type: 'static' do
      it_behaves_like 'succeeds'
    end

    context 'with dynamic registration', registration_type: 'dynamic' do
      it_behaves_like 'succeeds'
    end
  end
end
