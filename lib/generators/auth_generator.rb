class AuthGenerator < Rails::Generators::Base
  

  def declare_game_dependencies
    gem 'bcrypt', '~> 3.1.7'
    gem "haml-rails"
    gem_group :development, :test do
      gem "letter_opener"
    end
  end

  def configurate_development_environment_for_letter_opener
    inject_into_file "config/environments/development.rb", letter_opener_config, 
                      after: "Rails.application.configure do\n"
  end

	def generate_user_model_with_migration
		generate "model",  "User email:string:index password_digest remember_digest activation_digest activated:boolean activated_at:datetime reset_digest reset_sent_at:datetime"
	end

  def fill_user_model_with_code
    inject_into_class "app/models/user.rb", User, user_model_contents
  end

	def add_unique_contstraint
		inject_into_file search_for_create_user_migration, unique_constraint_string, after: "add_index :users, :email"
	end

	def g_users_controller
		generate "controller", "users"
	end

  def fill_users_controller
    inject_into_class "app/controllers/users_controller.rb", UsersController, users_controller_contents
  end

	def create_user_views
		create_file users_new_view_file
		create_file users_show_view_file
	end

	def fill_user_views_with_code
		append_to_file users_new_view_file, users_new_view_contents
    append_to_file users_show_view_file, users_show_view_contents
	end

  def g_sessions_controller
    generate "controller", "sessions"
  end

  def fill_sessions_controller_with_code
    inject_into_class "app/controllers/sessions_controller.rb", SessionsController, sessions_controller_contents
  end

  def create_session_views
    create_file "app/views/sessions/new.html.haml"
    create_file "app/views/sessions/_user_bar.html.haml"
  end

  def fill_session_views_with_content
    append_to_file "app/views/sessions/new.html.haml", sessions_new_view_contents
    append_to_file "app/views/sessions/_user_bar.html.haml", sessions_user_bar_partial_contents 
  end

  def create_session_helper_and_fill_it_with_content
    create_file "app/helpers/sessions_helper.rb" 
    append_to_file "app/helpers/sessions_helper.rb", sessions_helper_contents
  end

  def include_sessions_helper_in_application_controller
    inject_into_file "app/controllers/application_controller.rb", "include SessionsHelper\n", 
                      after: "protect_from_forgery with: :exception\n"
  end

  def g_password_resets_controller
    generate "controller", "password_resets"
  end

  def fill_password_resets_controller_with_code
    inject_into_class "app/controllers/password_resets_controller.rb", PasswordResetsController, password_resets_controller_contents
  end

  def create_password_resets_views_and_fill_them_with_content
    create_file(p_r_edit_file = "app/views/password_resets/edit.html.haml")
    create_file(p_r_new_file = "app/views/password_resets/new.html.haml")
    append_to_file p_r_edit_file, password_resets_edit_view_contents
    append_to_file p_r_new_file, password_resets_new_view_contents
  end

  def g_account_activations_controller
    generate "controller", "account_activations"
  end

  def fill_account_activations_controller_with_code
    inject_into_class "app/controllers/account_activations_controller.rb", AccountActivationsController, account_activations_controller_contents
  end

  def create_application_mailer_and_fill_it_with_contents
    create_file a_m = "app/mailers/application_mailer.rb"
    append_to_file a_m, application_mailer_contents
  end

  def create_application_mailer_views_and_layouts_and_fill_it_with_content
    create_file m_l_html = "app/views/layouts/mailer.html.haml"
    create_file m_l_text = "app/views/layouts/mailer.text.erb"

    append_to_file m_l_html, mailer_layout_html_contents
    append_to_file m_l_text, mailer_layout_text_contents
  end

  def create_user_mailer
    create_file "app/mailers/user_mailer.rb"
  end

  def fill_users_mailer_with_contents
    append_to_file "app/mailers/user_mailer.rb", user_mailer_contents
  end

  def create_user_mailer_views_and_fill_them_with_content
    create_file a_a_mailer_html = "app/views/user_mailer/account_activation.html.haml"
    create_file a_a_mailer_text = "app/views/user_mailer/account_activation.text.erb"

    create_file p_r_mailer_html = "app/views/user_mailer/password_reset.html.haml"
    create_file p_r_mailer_text = "app/views/user_mailer/password_reset.text.erb"

    append_to_file a_a_mailer_html, user_mailer_account_activation_view_html
    append_to_file a_a_mailer_text, user_mailer_account_activation_view_text

    append_to_file p_r_mailer_html, user_mailer_password_reset_view_html
    append_to_file p_r_mailer_text, user_mailer_password_reset_view_text
  end
  
  def configure_routes
    inject_into_file "config/routes.rb", routes_config, 
                      after: "Rails.application.routes.draw do\n"
  end

=begin
            


                PRIVATE METHODS



=end

 private

 	def search_for_create_user_migration
 		migration_file = Dir['db/migrate/*create_users.rb']
 		migration_file[0]
 	end

 	def unique_constraint_string
 		", unique: true"
 	end

 	def users_new_view_file
 		"app/views/users/new.html.haml"
 	end

 	def users_show_view_file
 		"app/views/users/show.html.haml"
 	end

  def account_activations_controller_contents
    %Q{
def edit
    user = User.find_by(email: params[:email])
    if user && !user.activated? && user.authenticated?(:activation, params[:id])
      user.activate
      log_in user
      flash[:success] = "Account activated!"
      redirect_to user
    else
      flash[:danger] = "Invalid activation link"
      redirect_to root_url
    end
end      
}
  end

=begin



            THE FILE CONTENT RETURNING METHODS



=end
  def users_controller_contents
    %Q{
=begin
IMPORTANT NOTICE
don't forget to insert this into application_controller
<div class="container">
  <div class="row-offset-3">
  <%= render "sessions/user_bar" %>
</div>
<% flash.each do |message_type, message| %>
  <div class="alert alert-<%= message_type %>"><%= message %></div>
<% end %>
=end
  before_action :logged_in_user, only: [:edit, :update]
  before_action :correct_user,   only: [:edit, :update]

  def show
    @user = User.find params[:id]
  end

  def new
    @user = User.new
  end

  def create
    @user = User.new(create_user_params)
    if @user.save
      if User::ACTIVATABLE
        @user.send_activation_email
        flash[:info] = "Please check your email to activate your account."
        redirect_to root_url
      else
        log_in @user
        #remember user
        flash[:success] = "confirmation email was sent"
        redirect_to @user
      end
    else
      render :new
    end

  end

  def create_user_params
    params.require(:user).permit(:email, :password, :password_confirmation)
  end

  # Confirms a logged-in user.
  def logged_in_user
    unless logged_in?
      store_location
      flash[:danger] = "Please log in."
      redirect_to login_url
    end
  end

  # Confirms the correct user.
  def correct_user
    @user = User.find(params[:id])
    redirect_to(root_url) unless current_user?(@user)
  end
    }
  end 

  def users_new_view_contents
    %Q{
.container
  %div.row
    = form_for(@user) do |f|
      - if @user.errors.any?
        .alert.alert-danger
          - @user.errors.full_messages.each do |message|
            %li
              = message
      = f.label :email
      = f.text_field :email
      %br
      = f.label :password
      = f.password_field :password
      %br
      = f.label :password_confirmation
      = f.password_field :password_confirmation
      %br
      = f.submit "sign up"
    } 
  end

  def users_show_view_contents
    %Q{
%div
  users#show
%br
- if logged_in?
  %div
    youre logged in as \#{current_user.email}
    %br
    = link_to "logout", logout_path, method: :DELETE
- else
  youre not logged in
  %br
  = link_to "login", login_path
    }
  end

  def sessions_new_view_contents
    %Q{
.row
  = form_for :session, url: login_path do |f|
    = f.label :email
    = f.email_field :email
    %br
    = f.label :password
    = f.password_field :password
    - #IF PASSWORD RESETABLE
    %p
      forgot your password? \#{link_to "reset password", new_password_reset_path}

    %br
    = f.label :remember_me do
      = f.check_box :remember_me
      %span
        remember me
    %br
    = f.submit "login"
    %br
    %p
      new user? \#{link_to "signup", sign_up_path}

}
  end

  def sessions_user_bar_partial_contents
    %Q{
- if logged_in?
  youre logged in as \#{current_user.email}
  = link_to "logout", logout_path, method: :delete
- else
  = link_to "login", login_path
}
  end

  def sessions_helper_contents
    %Q{
module SessionsHelper

  def log_in(user)
    session[:user_id] = user.id
  end

  def current_user
    if (user_id = session[:user_id])
      @current_user ||= User.find_by(id: user_id)
    elsif (user_id = cookies.signed[:user_id])
      user = User.find_by(id: user_id)
      if user && user.authenticated?(:remember, cookies[:remember_token])
        log_in user
        @current_user = user
      end
    end
  end

  def logged_in?
    !current_user.nil?
  end

  def forget(user)
    user.forget
    cookies.delete(:user_id)
    cookies.delete(:remember_token)
  end

  def log_out
    forget(current_user)
    session.delete(:user_id)
    @current_user = nil
  end

  def remember(user)
    user.remember
    cookies.permanent.signed[:user_id] = user.id
    cookies.permanent[:remember_token] = user.remember_token
  end

  def current_user?(user)
    user == current_user
  end

  # Redirects to stored location (or to the default).
  def redirect_back_or(default)
    redirect_to(session[:forwarding_url] || default)
    session.delete(:forwarding_url)
  end

  # Stores the URL trying to be accessed.
  def store_location
    session[:forwarding_url] = request.url if request.get?
  end
end
}
  end

  def sessions_controller_contents
    %Q{
  def new
  end

  def create
    user = User.find_by(email: params[:session][:email].downcase)
    if user && user.authenticate(params[:session][:password])
      if User::ACTIVATABLE
        if user.activated?
          log_in user
          params[:session][:remember_me] == '1' ? remember(user) : forget(user)
          redirect_back_or user
        else
          message  = "Account not activated. "
          message += "Check your email for the activation link."
          flash[:warning] = message
          redirect_to root_url
        end
      else
        log_in user
        params[:session][:remember_me] == '1' ? remember(user) : forget(user)
        redirect_back_or user
      end
    else  
      flash.now[:danger] = "invalid credentials"
      render :new
    end
  end

  def destroy
    log_out if logged_in?
    redirect_to login_path
  end
}
  end

  def password_resets_controller_contents
    %Q{
before_action :get_user         , only: [:edit , :update]
  before_action :valid_user       , only: [:edit , :update]
  before_action :check_expiration , only: [:edit , :update]

  def new
  end

  def create
    @user =User.find_by email: params[:password_reset][:email].downcase
    if @user
      @user.create_reset_digest
      @user.send_password_reset_email
      flash[:info] = "email sent with password reset instructions"
      redirect_to root_url
    else
      flash.now[:danger] = "error occured"
      render :new
    end
  end

  def edit
    
  end

  def update
    if params[:user][:password].empty?
      @user.errors.add(:password, "can't be empty")
      render :edit
    elsif @user.update_attributes(user_params)
      log_in @user
      flash[:success] = "password has been reset successflly"
      redirect_to @user
    else
      render :new
    end
  end

 private
  
  def user_params
    params.require(:user).permit(:password, :password_confirmation)
  end


  def get_user
    @user = User.find_by email: params[:email]
  end 

  def valid_user
    unless (  @user && @user.activated? &&
              @user.authenticated?(:reset, params[:id]) )
      redirect_to root_url      
    end
  end

  def check_expiration
    if @user.password_reset_expired?
      flash[:danger] = "password reset expired"
      redirect_to new_password_reset_url
    end
  end
}
  end

  def password_resets_edit_view_contents
    %Q{
%div
  reset password
.row
  = form_for @user, url: password_reset_path(params[:id]) do |f|
    
    = hidden_field_tag :email, @user.email

    = f.label          :password
    = f.password_field :password
    %br
    = f.label          :password_confirmation, "confirmation"
    = f.password_field :password_confirmation
    %br
    = f.submit "update password"
}
  end

  def password_resets_new_view_contents
    %Q{
%div
  PASSWORD RESET

.row
  = form_for :password_reset, url: password_resets_path do |f|
    = f.label       :email
    = f.email_field :email
    %br
    = f.submit "submit"
}
  end

  def user_mailer_contents
    %Q{
class UserMailer < ApplicationMailer

  # Subject can be set in your I18n file at config/locales/en.yml
  # with the following lookup:
  #
  #   en.user_mailer.account_activation.subject
  #
  def account_activation(user)
    @user = user
    mail to: user.email, subject: "account activation"
  end

  # Subject can be set in your I18n file at config/locales/en.yml
  # with the following lookup:
  #
  #   en.user_mailer.password_reset.subject
  #
  def password_reset(user)
    @user = user
    mail to: user.email, subject: "password reset"
  end
end
}
  end

  def user_mailer_account_activation_view_html
    %Q{
%div
  Hi \#{@user.email}
%div
  Welcome! Click on the link below to activate your account:
  \#{edit_account_activation_url(@user.activation_token, email: @user.email)}
}
  end

  def user_mailer_account_activation_view_text
    %Q{
Hi <%= @user.email =>

Welcome! Click on the link below to activate your account:
<%= edit_account_activation_url(@user.activation_token, email: @user.email) >
}
  end

  def user_mailer_password_reset_view_html
    %Q{
%div
  to reset your password click the link below:
%p
  = link_to "reset link",edit_password_reset_url(@user.reset_token, email: @user.email)
  %br
  this link will expire in two hours.
  if you didnt requset password reset, ignore this, and your password will be unchanged
}
  end

  def user_mailer_password_reset_view_text
    %Q{
To reset your password click the link below:

<%= edit_password_reset_url(@user.reset_token, email: @user.email) %>

This link will expire in two hours.

If you did not request your password to be reset, please ignore this email and
your password will stay as it is.
}
  end

  def user_model_contents
    <<-'EOS'
#AUTHENTICATION

  ACTIVATABLE = true
  
  attr_accessor :activation_token #ACTIVATION

  attr_accessor :reset_token
  
  attr_accessor :remember_token

  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i

  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX },
                    uniqueness: { case_sensitive: false }
  
  validates :password, presence: true, length: { minimum: 6 }

  before_save :downcase_email

  before_create :create_activation_digest #ACTIVATION

  has_secure_password 

  def self.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                 BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  def self.new_token
    SecureRandom.urlsafe_base64
  end

  def remember
    self.remember_token = self.class.new_token
    update_attribute(:remember_digest, self.class.digest(remember_token))
  end

  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end

  def forget
    update_attribute(:remember_digest, nil)
  end

  def downcase_email
    self.email = email.downcase 
  end

  def create_activation_digest
    self.activation_token = self.class.new_token
    self.activation_digest =  self.class.digest(activation_token)
  end

  def activate
    update_attribute :activated, true
    update_attribute :activated_at, Time.zone.now
  end

  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end

  def create_reset_digest # RESET PASSWORD
    self.reset_token = self.class.new_token
    self.update_attribute(:reset_digest, self.class.digest(reset_token))
    self.update_attribute(:reset_sent_at, Time.zone.now)
  end

  def send_password_reset_email
    UserMailer.password_reset(self).deliver_now
  end

  def password_reset_expired?
    self.reset_sent_at < 2.hours.ago
  end
  #//////
EOS
  end

  def application_mailer_contents
    %Q{
class ApplicationMailer < ActionMailer::Base
  default from: "from@example.com"
  layout 'mailer'
end
}
  end

  def mailer_layout_html_contents
    %Q{
%html
 %body
  = yield
}
  end

  def mailer_layout_text_contents
    %Q{
<%= yield %>
}
  end

  def letter_opener_config
    %Q{
  #########CHANGED
  config.action_mailer.delivery_method = :letter_opener
  config.action_mailer.default_url_options = { :host => "localhost:3000" }
  #########END CHANGED
}
  end
  
  def routes_config
    %Q{
# BASIC AUTH
  get "sign_up" => "users#new"
  resources :users, except: [:new]
  get    'login'  => 'sessions#new'
  post   'login'  => 'sessions#create'
  delete 'logout' => 'sessions#destroy'
  #ACCOUNT ACTIVATION
  resources :account_activations, only: [:edit]
  #PASSWORD RESETS
  resources :password_resets, only: [:new, :create, :edit, :update]
# END BASIC AUTH      
    }
  end
end
