class PicoMoney < ActiveRecord::Base
  extend ActiveSupport::Memoizable

  belongs_to :account

  validate :identifier, presence: true, uniqueness: true
  validate :_token_,    presence: true, uniqueness: true
  validate :secret,     presence: true
  validate :profile,    url: true
  validate :thumbnail,  url: true

  def identity
    handle_response({}) do
      access_token.get '/about_user'
    end
  end
  memoize :identity

  private

  def access_token
    OAuth::AccessToken.new(self.class.client, self._token_, self.secret)
  end

  def handle_response(failure_response = nil)
    response = yield
    JSON.parse(response.body).with_indifferent_access
  rescue => e
    case e
    when OAuth::Unauthorized
      destroy
    else
      # something others?
    end
    failure_response
  end

  class << self
    extend ActiveSupport::Memoizable

    def config
      YAML.load_file("#{Rails.root}/config/pico_money.yml")[Rails.env].symbolize_keys
    rescue Errno::ENOENT => e
      raise StandardError.new("config/pico_money.yml could not be loaded.")
    end
    memoize :config

    def client
      OAuth::Consumer.new(
        config[:consumer_key],
        config[:consumer_secret],
        site: config[:site]
      )
    end

    def organization
      find_by_identifier!(config[:organization])
    end
    memoize :organization

    def transaction_url
      File.join(config[:site], config[:currency])
    end

    def request_token!(callback)
      client.get_request_token({oauth_callback: callback}, {scope: transaction_url})
    end

    def access_token!(token, secret, code)
      OAuth::RequestToken.new(client, token, secret).get_access_token(oauth_verifier: code)
    end

    def authenticate!(token, secret, code)
      access_token = access_token!(token, secret, code)
      identity = new(
        _token_: access_token.token,
        secret:  access_token.secret
      ).identity
      pico = find_or_initialize_by_identifier(identity[:login])
      pico.update_attributes!(
        _token_:   access_token.token,
        secret:    access_token.secret,
        profile:   identity[:profile],
        thumbnail: identity[:thumbnail_url]
      )
      pico.account || Account.create!(pico_money: pico)
    end
  end

end
