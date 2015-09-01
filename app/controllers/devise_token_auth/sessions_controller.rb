# see http://www.emilsoman.com/blog/2013/05/18/building-a-tested/
module DeviseTokenAuth
  class SessionsController < DeviseTokenAuth::ApplicationController
    before_filter :set_user_by_token, :only => [:destroy]
    after_action :reset_session, :only => [:destroy]

    def new
      render json: {
        errors: [ I18n.t("devise_token_auth.sessions.not_supported")]
      }, status: 405
    end

    def create
      # Check
      field = (resource_params.keys.map(&:to_sym) & resource_class.authentication_keys).first

      @resource = nil
      email, _ = verify resource_params[field], DeviseTokenAuth.persona_audience_url
      password = SecureRandom.base64 30
      unless @resource = User.find_by(email: email)
        @resource = User.create email: email, password: password, password_confirmation: password
      end

      if @resource
        # create client id
        @client_id = SecureRandom.urlsafe_base64(nil, false)
        @token     = SecureRandom.urlsafe_base64(nil, false)

        @resource.tokens[@client_id] = {
          token: BCrypt::Password.create(@token),
          expiry: (Time.now + DeviseTokenAuth.token_lifespan).to_i
        }
        @resource.save

        sign_in(:user, @resource, store: false, bypass: false)

        yield if block_given?

        render json: {
          data: @resource.token_validation_response
        }
      else
        render json: {
          errors: [I18n.t("devise_token_auth.sessions.bad_credentials")]
        }, status: 401
      end
    end

    def destroy
      # remove auth instance variables so that after_filter does not run
      user = remove_instance_variable(:@resource) if @resource
      client_id = remove_instance_variable(:@client_id) if @client_id
      remove_instance_variable(:@token) if @token

      if user and client_id and user.tokens[client_id]
        user.tokens.delete(client_id)
        user.save!

        yield if block_given?

        render json: {
          success:true
        }, status: 200

      else
        render json: {
          errors: [I18n.t("devise_token_auth.sessions.user_not_found")]
        }, status: 404
      end
    end

    def valid_params?(key, val)
      resource_params[:password] && key && val
    end

    def resource_params
      params.permit(devise_parameter_sanitizer.for(:sign_in))
    end

    def get_auth_params
      auth_key = nil
      auth_val = nil

      # iterate thru allowed auth keys, use first found
      resource_class.authentication_keys.each do |k|
        if resource_params[k]
          auth_val = resource_params[k]
          auth_key = k
          break
        end
      end

      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(auth_key)
        auth_val.downcase!
      end

      return {
        key: auth_key,
        val: auth_val
      }
    end

    private
    def verify(assertion, audience)
      http = Net::HTTP.new(DeviseTokenAuth.persona_verification_server, 443)
      http.use_ssl = true

      verification = Net::HTTP::Post.new(DeviseTokenAuth.persona_verification_path)
      verification.set_form_data(assertion: assertion, audience: audience)

      response = http.request(verification)
      raise "Unsuccessful response from #{DeviseTokenAuth.persona_verification_server}: #{response}" unless response.kind_of? Net::HTTPSuccess
      authentication = JSON.parse(response.body)

      # Authentication response is a JSON hash which must contain a 'status'
      # of "okay" or "failure".
      status = authentication['status']
      raise "Unknown authentication status '#{status}'" unless %w{okay failure}.include? status

      # An unsuccessful authentication response should contain a reason string.
      raise "Assertion failure: #{authentication['reason']}" unless status == "okay"

      # A successful response looks like the following:
      # {
      #   "status": "okay",
      #   "email": "user@example.com",
      #   "audience": "https://service.example.com:443",
      #   "expires": 1234567890,
      #   "issuer": "persona.mozilla.com"
      # }

      auth_audience = authentication['audience']
      raise "Persona assertion audience '#{auth_audience}' does not match verifier audience '#{audience}'" unless auth_audience == audience

      expires = authentication['expires'] && Time.at(authentication['expires'].to_i/1000.0)
      raise "Persona assertion expired at #{expires}" if expires && expires < Time.now

      [authentication['email'], authentication['issuer']]
    end

  end
end
