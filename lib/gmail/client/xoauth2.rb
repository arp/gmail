require 'gmail_xoauth'

module Gmail
  module Client
    class XOAuth2 < Base
      attr_reader :token

      def initialize(username, options={})
        @token           = options.delete(:token)
        @expires_at      = options.delete(:expires_at)
        @refresh_token   = options.delete(:refresh_token)
        @client_id       = options.delete(:client_id)
        @client_secret   = options.delete(:client_secret)

        super(username, options)
      end

      def login(raise_errors=false)
        refresh_token if Time.now.utc > @expires_at
        @imap and @logged_in = (login = @imap.authenticate('XOAUTH2', username, token)) && login.name == 'OK'
      rescue
        raise_errors and raise AuthorizationError, "Couldn't login to given GMail account: #{username}"        
      end

      def smtp_settings
        [:smtp, {
           :address => GMAIL_SMTP_HOST,
           :port => GMAIL_SMTP_PORT,
           :domain => mail_domain,
           :user_name => username,
           :password => {
             :token           => token
           },
           :authentication => :xoauth2,
           :enable_starttls_auto => true
         }]
      end
    end # XOAuth

    register :xoauth2, XOAuth2

    private

    def refresh_token
      data = {
        client_id:     @client_id,
        client_secret: @client_secret,
        refresh_token: @refresh_token,
        grant_type:    "refresh_token"
      }
      response = JSON.parse(RestClient.post "https://accounts.google.com/o/oauth2/token", data)
      @token = response["access_token"] unless response["access_token"].nil?
    end
  end # Client
end # Gmail
