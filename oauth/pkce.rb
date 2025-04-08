# frozen_string_literal: true

module OAuth
  class PKCE
    # I don't think PKCE is strictly an OAuth concept...

    SUPPORTED_CODE_CHALLENGE_VERSION = 'S256'

    class << self
      def supported?(method)
        method == SUPPORTED_CODE_CHALLENGE_VERSION
      end

      def generate_code_verifier
        "code-verifier:#{SecureRandom.hex(10)}"
      end

      def generate_code_challenge(verifier)
        one_way_transformation(verifier)
      end

      def valid_code_challenge?(stored_challenge:, provided_verifier:)
        stored_challenge == one_way_transformation(provided_verifier)
      end

      private

      def one_way_transformation(element)
        Base64.urlsafe_encode64(Digest::SHA2.hexdigest(element))
      end
    end
  end
end
