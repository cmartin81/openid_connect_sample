class IdToken < ActiveRecord::Base
  belongs_to :account
  belongs_to :client
  has_one :id_token_request_object
  has_one :request_object, through: :id_token_request_object

  before_validation :setup, on: :create

  validates :account, presence: true
  validates :client,  presence: true

  scope :valid, lambda {
    where { expires_at >= Time.now.utc }
  }

  def to_response_object(with = {})
    subject = if client.ppid?
      account.ppid_for(client.sector_identifier).identifier
    else
      account.identifier
    end
    claims = {
      iss: self.class.config[:issuer],
      sub: subject,
      aud: client.identifier,
      nonce: nonce,
      exp: expires_at.to_i,
      iat: created_at.to_i
    }
    if accessible?(:auth_time)
      claims[:auth_time] = account.last_logged_in_at.to_i
    end
    if accessible?(:acr)
      required_acr = request_object.to_request_object.id_token.claims[:acr].try(:[], :values)
      if required?(:acr) && required_acr && !required_acr.include?('0')
        # TODO: return error, maybe not this place though.
      end
      claims[:acr] = '0'
    end
    id_token = OpenIDConnect::ResponseObject::IdToken.new(claims)
    id_token.code = with[:code] if with[:code]
    id_token.access_token = with[:access_token] if with[:access_token]
    id_token
  end

  def to_jwt(with = {})
    to_response_object(with).to_jwt(self.class.config[:private_key]) do |jwt|
      jwt.kid = self.class.config[:kid]
    end
  end

  private

  def required?(claim)
    request_object.try(:to_request_object).try(:id_token).try(:required?, claim)
  end

  def accessible?(claim)
    request_object.try(:to_request_object).try(:id_token).try(:accessible?, claim)
  end

  def setup
    self.expires_at = 5.minutes.from_now
  end

  class << self
    def decode(id_token)
      OpenIDConnect::ResponseObject::IdToken.decode id_token, config[:public_key]
    rescue => e
      logger.error e.message
      nil
    end

    def config
      unless @config
        config_path = File.join Rails.root, 'config/connect/id_token'
        @config = YAML.load_file(File.join(config_path, 'issuer.yml'))[Rails.env].symbolize_keys
        @config[:jwks_uri] = File.join(@config[:issuer], 'jwks.json')
        private_key = OpenSSL::PKey::RSA.new(
          File.read(File.join(config_path, 'key.pem')),
          '1234'
        )
        cert = OpenSSL::X509::Certificate.new(
          File.read(File.join(config_path, 'cert.pem'))
        )
        @config[:kid] = :default
        @config[:public_key]  = cert.public_key
        @config[:private_key] = private_key
        @config[:jwk_set] = JSON::JWK::Set.new(
          JSON::JWK.new(cert.public_key, use: :sig, kid: @config[:kid])
        )

        a = JSON.parse(@config[:jwk_set].to_json)
        a['keys'][0][:x5c] = ['MIIE6DCCA9CgAwIBAgIJANCL84Hk+Ci1MA0GCSqGSIb3DQEBBQUAMIGoMQswCQYD
VQQGEwJOTzEaMBgGA1UECBMRSHZhbHN0YWQgZG93bnRvd24xETAPBgNVBAcTCEh2
YWxzdGFkMRcwFQYDVQQKEw5Tb3JuZWQgVEVTVElORzEOMAwGA1UECxMFYmxhbGEx
GTAXBgNVBAMTEENocmlzdGlhbiBNYXJ0aW4xJjAkBgkqhkiG9w0BCQEWF2Nocmlz
dGlhbkB0b3BtYXJ0aW4uY29tMB4XDTE2MDMxMTExNDMzN1oXDTIwMDQxOTExNDMz
N1owgagxCzAJBgNVBAYTAk5PMRowGAYDVQQIExFIdmFsc3RhZCBkb3dudG93bjER
MA8GA1UEBxMISHZhbHN0YWQxFzAVBgNVBAoTDlNvcm5lZCBURVNUSU5HMQ4wDAYD
VQQLEwVibGFsYTEZMBcGA1UEAxMQQ2hyaXN0aWFuIE1hcnRpbjEmMCQGCSqGSIb3
DQEJARYXY2hyaXN0aWFuQHRvcG1hcnRpbi5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCd9vnlzErwjhpliKcLmf1yQFc0sK7i8gVdIidg6UBJjw/z
XlP6yOuD337+IaRr3PUVqGZ7AiGDU9cIlbc4/L6gxMZ3MgfCJI21I94KlWsenSgA
HT5kNkbg+lv+6n7Clw79idcc3YWbOQJJ+fJnzzGKPXhf/HWzb5An4Ybrf4+pJHoE
JQfA4mKOsnTz6HQlGDvRIkf+LzUss3vYZfKmft5IiYxZdpRfJP3fgTYypvVfk/4j
HMm1aZ0n0zdQEQ1GDNwBoYVT9Hv/Vv4MUq0Zf2+wSb1dhXPy91TQUDSTuoCATjKy
UzDzpq3iG/WSzH/ciINd6vrBqqTBTloSKfiw12rTAgMBAAGjggERMIIBDTAdBgNV
HQ4EFgQUjkQVyjERFvU25R21hGjlHKS5Mtowgd0GA1UdIwSB1TCB0oAUjkQVyjER
FvU25R21hGjlHKS5Mtqhga6kgaswgagxCzAJBgNVBAYTAk5PMRowGAYDVQQIExFI
dmFsc3RhZCBkb3dudG93bjERMA8GA1UEBxMISHZhbHN0YWQxFzAVBgNVBAoTDlNv
cm5lZCBURVNUSU5HMQ4wDAYDVQQLEwVibGFsYTEZMBcGA1UEAxMQQ2hyaXN0aWFu
IE1hcnRpbjEmMCQGCSqGSIb3DQEJARYXY2hyaXN0aWFuQHRvcG1hcnRpbi5jb22C
CQDQi/OB5PgotTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAO+8Ts
yIH+K7LWAxIyqg1T111MLJFGPItzRbliFyHanVDcA3m6APNzNxBuXhs0DVogPZua
ypPjWOIaxg76aHHPnAAH85GPYJaMFY180LAQ5uZLT2TQZSb4vUTX2te6+JMTrpZm
lbPssuy/cjoDCMuAjbrk3iPL/PMrnDx/t4/R0ulO9MBmSINkKLsKJGcGKfOIjxK7
ohCE89EqzVjGX4JnSd11Ol7qQEDdBVRRyI2qrv/LsDsrVBPvTu3rtK20raGOVSkl
RtopUXDNPuTqd5MbDExsrgjexXkJ/vh6AJXfgyGPL10CU4LpTcXZQCFFU5ahZ7t7
kOgyd7zV8pdPkQa/']




        @config[:jwk] = a



      end
      @config
    end
  end
end