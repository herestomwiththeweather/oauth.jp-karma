class PicoMoney < ActiveRecord::Base
  extend ActiveSupport::Memoizable

  belongs_to :account

  validates :account_id, uniqueness: true,                allow_nil: true
  validates :identifier, uniqueness: true, presence: true
  validates :token,      uniqueness: true, presence: true
  validates :secret,                       presence: true
  validates :email_md5,  uniqueness: true,                 allow_nil: true
  validates :profile,                      presence: true, url: true
  validates :thumbnail,                    presence: true, url: true

  def identity
    handle_response({}) do
      access_token.get '/about_user'
    end
  end
  memoize :identity

  def wallet
    handle_response({}) do
      access_token.get "/wallet"
    end
  end
  memoize :wallet

  def karma
    Array(wallet[:assets]).detect do |asset|
      asset[:url] == self.class.transaction_url
    end || {}
  end

  private

  def access_token
    OAuth::AccessToken.new(self.class.client, self.token, self.secret)
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

    def issuer
      find_by_identifier!(config[:issuer])
    end
    memoize :issuer

    def transaction_url
      File.join(config[:site], '/transacts', config[:currency])
    end

    def request_token!(callback)
      amount = 1000
      scope1 = config[:site] + '/scopes/wallet.json'
      scope2 = config[:site] + '/scopes/single_payment.json?asset=' + config[:currency] + '&amount=' + amount.to_s
      scope3 = config[:site] + '/scopes/list_payments.json'
      scope = scope1 + ' ' + scope2 + ' ' + scope3

      client.get_request_token({oauth_callback: callback}, {scope: scope})
    end

    def access_token!(token, secret, code)
      OAuth::RequestToken.new(client, token, secret).get_access_token(oauth_verifier: code)
    end

    def authenticate!(token, secret, code)
      logger.info "XXX authenticate!"
      access_token = access_token!(token, secret, code)
      identity = new(
        token:  access_token.token,
        secret: access_token.secret
      ).identity
      logger.info "XXX identity"
      logger.info "XXX login: #{identity[:login]}"
      logger.info "XXX email_md5: #{identity[:email_md5]}"
      logger.info "XXX profile: #{identity[:profile]}"
      logger.info "XXX thumbnail_url: #{identity[:thumbnail_url]}"
      pico = find_or_initialize_by_identifier(identity[:login])
      pico.update_attributes!(
        token:     access_token.token,
        secret:    access_token.secret,
        email_md5: identity[:email_md5],
        profile:   identity[:profile],
        thumbnail: identity[:thumbnail_url]
      )
      pico.account || Account.create!(pico_money: pico)
    end
  end

end
