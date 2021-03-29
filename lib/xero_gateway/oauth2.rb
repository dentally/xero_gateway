module XeroGateway
  class OAuth2

    class TokenExpired < StandardError; end
    class TokenInvalid < StandardError; end
    class RateLimitExceeded < StandardError; end
    class UnknownError < StandardError; end

    XERO_CLIENT_OPTIONS = {
      authorize_url: "https://login.xero.com/identity/connect/authorize",
      token_url: "https://identity.xero.com/connect/token",
      site: "https://api.xero.com/api.xro/2.0",
      raise_errors: false
    }

    attr_reader :client_id, :client_secret, :client_options, :authorization_expires_at, :expires_at

    def initialize(client_id, client_secret, options = {})
      @client_id, @client_secret = client_id, client_secret

      @base_headers = {}
      @base_headers["User-Agent"] = options.delete(:user_agent) if options.has_key?(:user_agent)
      @base_headers["Xero-tenant-id"] = options.delete(:xero_tenant_id) if options.has_key?(:xero_tenant_id)

      @client_options = XERO_CLIENT_OPTIONS.merge(options)
    end

    def client
      @client ||= ::OAuth2::Client.new(client_id, client_secret, client_options)
    end

    def request_token(params = {})
      client.auth_code.authorize_url(params)
    end

    def authorize_from_request(code, options = {})
      auth_header = Base64.strict_encode64(client_id + ":" + client_secret)
      options.merge!({
        grant_type: "authorization_code",
        headers: {
          "Authorization" => "Basic #{auth_header}"
        }
      })
      token = client.auth_code.get_token(code, options)
      update_attributes_from_token(token)
    end

    def access_token
      @access_token
    end

    def authorize_from_access(token_hash)
      token = ::OAuth2::AccessToken.from_hash(client, token_hash)
      update_attributes_from_token(token)
    end

    def renew_access_token
      token = @access_token.refresh!
      update_attributes_from_token(token)
    end

    def get(path, headers = {})
      access_token.get(path, headers: headers.merge(@base_headers))
    end

    def post(path, body = '', headers = {})
      access_token.post(path, { body: body, headers: headers.merge(@base_headers) })
    end

    def put(path, body = '', headers = {})
      access_token.put(path, { body: body, headers: headers.merge(@base_headers) })
    end

    def delete(path, headers = {})
      access_token.delete(path, headers: headers.merge(@base_headers))
    end

    private

    # Update instance variables with those from the AccessToken.
    def update_attributes_from_token(token)
      @expires_at  = Time.at(token.expires_at)
      @authorization_expires_at = Time.at(token.expires_at)
      @access_token = token
    end
  end
end
