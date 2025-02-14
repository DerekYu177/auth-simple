# frozen_string_literal: true

require_relative './auth_server'

require 'minitest/autorun'
require 'rack/test'
require 'debug'

class AuthServerTest < ActiveSupport::TestCase
  include Rack::Test::Methods

  def test_full_unauthorized_flow
    get('/admin')

    assert_equal '/oauth/authorize', URI(last_response['location']).path
    assert_predicate last_response, :redirect?

    follow_redirect!

    assert_equal '/admin/callback', URI(last_response['location']).path
    assert_predicate last_response, :redirect?

    follow_redirect!

    assert_equal '/admin', URI(last_response['location']).path
    assert_predicate last_response, :redirect?

    follow_redirect!

    response = JSON.parse(last_response.body)
    assert_equal 'authenticated', response['result']
  end

  def test_authorize_returns_success
    get(
      '/oauth/authorize',
      client_id: ResourceServer::CLIENT_ID,
      code_challenge: 'random',
      code_challenge_method: 'S256',
      authenticated: 1,
      response_type: 'code'
    )
    query = parse_redirect(last_response)

    assert_includes query, 'code'
    assert_equal 'valid-grant', query['code']

    uri = URI(last_response['location'])
    assert_equal '/admin/callback', uri.path
  end

  def test_authorize_error_redirects
    get(
      '/oauth/authorize',
      client_id: ResourceServer::CLIENT_ID,
      code_challenge: 'random',
      code_challenge_method: 'S256',
      authenticated: 2,
      response_type: 'code'
    )
    query = parse_redirect(last_response)

    assert_includes query, 'error'
    assert_includes query, 'error_description'
  end

  def test_tokens_returns_access_token
    # assume we have the token here
    post(
      '/oauth/tokens',
      grant_type: 'authorization_code',
      code: 'valid-grant',
      client_id: ResourceServer::CLIENT_ID
    )

    response = JSON.parse(last_response.body)

    assert_includes response, 'access_token'
    assert_includes response, 'token_type'
  end

  def test_tokens_error_if_unrecognized
    post(
      '/oauth/tokens',
      grant_type: 'unsupported'
    )

    query = parse_redirect(last_response)

    assert_includes query, 'error'
    assert_includes query, 'error_description'

    assert_equal 'unsupported_grant_type', query['error']
  end

  def default_host
    'localhost'
  end

  private

  def parse_redirect(response)
    assert_predicate response, :redirect?
    redirect_to = response['location']

    uri = URI(redirect_to)
    Rack::Utils.parse_query(uri.query)
  end

  def app
    Rails.application
  end
end
