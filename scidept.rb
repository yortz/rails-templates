run "echo TODO > README"
run 'rm public/javascripts/*'

gem 'rspec', :lib => "spec", :version => "1.2.9"
gem 'rspec-rails', :lib => "spec/rails", :version => "1.2.9"
gem 'cucumber', :version => '0.4.4'
gem 'webrat', :version => "0.5.3"
gem 'fixjour', :lib => "fixjour", :version => "0.2.1"
gem "email_spec", :lib => "email_spec", :version => "0.3.5"

gem 'authlogic', :lib => "authlogic", :verson => "2.1.3"
gem 'less', :version => "1.2.11", :lib => false
gem 'more', :version => "0.0.3"
gem 'flash-mesage-conductor', :lib => "flash_message_conductor"
gem "jrails", :version => "0.6.0"

rake "gems:install"

plugin "accessible_form_builder", :git => "git://github.com/BJClark/accessible_form_builder.git"

generate :rspec
generate :cucumber

run "rm public/index.html"

run "git clone git://github.com/davemerwin/960-grid-system.git"
run "mkdir public/stylesheets/960gs"
run "cp 960-grid-system/code/css/*.css public/stylesheets/960gs"
run "rm -rf 960-grid-system"
run "touch public/stylesheets/screen.less"
run "touch public/stylesheets/print.less"

run 'echo Less::More.source_path = Rails.root + "/public/stylesheets" >> config/environment.rb'

run "mkdir assets"

run "rm -rf test"

git :init

file ".gitignore", <<-END
.DS_Store
log/*.log
tmp/**/*
config/database.yml
.idea
.generators
public/stylesheets/*.css
END

run "cp config/database.yml config/example_database.yml"

git :add => "."
git :commit => "-m 'Initial commit'"

run "createuser -s #{self.root}"
rake "db:create"

session_class = ask("\nHello, what should I call your session model (ex 'user_session')?")
user_class = ask("\nHello, what should I call your 'user' model (ex 'user')?")

generate :session, session_class
generate :scaffold_resource, session_class.pluralize, "-s", "--skip-migration"

file("app/views/layouts/application.html.erb") do
  <<-EOF
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>

    <title><%= @title ||= "My App" %></title>
    <%= stylesheet_link_tag "960gs/reset", :media => "screen, projection" %>
    <%= stylesheet_link_tag "960gs/960", :media => "screen, projection" %>
    <%= stylesheet_link_tag "960gs/text", :media => "screen, projection" %>
    <%= stylesheet_link_tag "good_forms", :media => "screen, projection" %>
    <%= stylesheet_link_tag "screen", :media => "screen, projection" %>
    <%= stylesheet_link_tag "print", :media => "print" %>

    <%= javascript_include_tag :defaults %>
</head>

<body>
    <div class="container_16">
        <%= render_flash_messages %>
        <%= yield %>
    </div>
</body>
</html>

  EOF
end

file("app/views/#{session_class.pluralize}/new.html.erb") do
  <<-EOF
<h1>Login</h1>

<% af_form_for @#{session_class}, :url => #{session_class}_path do |f| %>
  <%= f.error_messages %>
  <%= f.text_field :email %>
  <%= f.password_field :password %>
  <%= f.check_box :remember_me %>
  <%= f.submit "Login" %>
<% end %>

  EOF
end

file("app/controllers/#{session_class.pluralize}_controller.rb") do
  <<-EOF
class #{session_class.camelize.pluralize}Controller < ResourceController::Singleton
  create.success.wants.html { redirect_to #{user_class}_path(current_#{user_class}.id) }
  create.failure.wants.html { render :action => "new" }
  create do
    success.wants.html { redirect_to user_path(current_user) }
    success.flash "You should receive an email to confirm your account. Please click on the link to activate your account."
    failure.wants.html { render :action => "new" }
  end
  destroy.wants.html { redirect_to root_path }

  private
  def object
    @object ||= #{session_class.camelize}.find
  end
end
  EOF
end

route "map.resource :#{session_class}, :member => {:destroy => :any}"

generate :scaffold_resource, user_class, "email:string", "crypted_password:string", "password_salt:string", "persistence_token:string", "single_access_token:string", "perishable_token:string", "last_login_at:datetime", "active:boolean"

file("app/models/#{user_class}.rb") do
  <<-EOF
class User < ActiveRecord::Base
  attr_accessible :email, :password, :password_confirmation
  
  acts_as_authentic

  def to_params
    self.id
  end

  def activate!
   self.active = true
   save!
  end

  def signup(params)
    self.email = params[:email]
    self.password = params[:password]
    self.password_confirmation = params[:password_confirmation]
    save_without_session_maintenance
  end

  def deliver_password_reset_instructions!
    reset_perishable_token!
    Notifier.deliver_password_reset_instructions(self)
  end

  def deliver_activation_instructions!
    reset_perishable_token!
    Notifier.deliver_activation_instructions(self)
  end

  def deliver_activation_confirmation!
    reset_perishable_token!
    Notifier.deliver_activation_confirmation(self)
  end

end
  EOF
end

file("app/controllers/#{user_class.pluralize}_controller.rb") do
  <<-EOF
class #{user_class.camelize.pluralize}Controller < ResourceController::Base
  before_filter :load_#{user_class}_using_perishable_token, :only => [:activate]
  before_filter :require_#{user_class}, :only => [:show, :update, :edit, :destroy]
  before_filter :require_no_#{user_class}, :only => [:new, :create]

  def create
    @#{user_class} = #{user_class.camelize}.new

    if @#{user_class}.signup(params[:#{user_class}])
      @#{user_class}.deliver_activation_instructions!
      add_notice "Your account has been created. Please check your e-mail for your account activation instructions!"
      redirect_to new_#{session_class}_path
    else
      render :action => :new
    end
  end

  def activate
    if @#{user_class}.activate!
      @#{user_class}.deliver_activation_confirmation!
      add_notice "Your account has been activated."
      redirect_to #{user_class}_path(@#{user_class})
    else
      add_error "Unable to active your account, please try again. If this error persists, contact support."
      render :action => :new
    end
  end

  destroy.success.wants.html { redirect_to new_user_path }

end
  EOF
end

file("spec/controllers/#{user_class.pluralize}_controller_spec.rb") do
  <<-EOF
require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe #{user_class.camelize.pluralize}Controller do
  before(:each) { activate_authlogic }

  describe "handling GET /#{user_class.pluralize}/new" do

    before(:each) do
      @#{user_class} = valid_#{user_class}
      #{user_class.camelize}.stub!(:new).and_return(@#{user_class})
      logout
    end

    def do_get
      get :new
    end

    it "should be successful" do
      do_get
      response.should be_success
    end

    it "should render new template" do
      do_get
      response.should render_template('new')
    end

    it "should create an new user" do
      #{user_class.camelize}.should_receive(:new).and_return(@#{user_class})
      do_get
    end

    it "should not save the new #{user_class}" do
      @#{user_class}.should_not_receive(:save)
      do_get
    end

    it "should assign the new #{user_class} for the view" do
      do_get
      assigns[:#{user_class}].should equal(@#{user_class})
    end
  end

  describe "handling GET /users/1/edit" do

    before(:each) do
      login
      @#{user_class} = valid_#{user_class}
      #{user_class.camelize}.stub!(:find).and_return(@#{user_class})
    end

    def do_get
      get :edit, :id => "1"
    end

    it "should be successful" do
      do_get
      response.should be_success
    end

    it "should render edit template" do
      do_get
      response.should render_template('edit')
    end

    it "should find the user requested" do
      #{user_class.camelize}.should_receive(:find).and_return(@#{user_class})
      do_get
    end

    it "should assign the found #{user_class.camelize.pluralize} for the view" do
      do_get
      assigns[:#{user_class}].should equal(@#{user_class})
    end
  end

  describe "handling POST /#{user_class.pluralize}" do

    before(:each) do
      @#{user_class} = valid_#{user_class}
      #{user_class.camelize}.stub!(:new).and_return(@#{user_class})
      @#{user_class}.stub!(:signup).and_return true
    end

    describe "with successful save" do
      def do_post
        post :create, :#{user_class} => {}
      end

      it "should create a new #{user_class}" do
        #{user_class.camelize}.should_receive(:new).and_return(@#{user_class})
        @#{user_class}.should_receive(:signup).and_return(true)
        do_post
      end

    end

    describe "with failed save" do

      def do_post
        @#{user_class}.should_receive(:signup).and_return(false)
        post :create, :#{user_class} => {}
      end

      it "should re-render 'new'" do
        do_post
        response.should render_template('new')
      end

    end
  end

  describe "handling DELETE /#{user_class.pluralize}/1" do

    before(:each) do
      @#{user_class} = valid_#{user_class}
      @#{user_class}.save
      #{user_class.camelize}.stub!(:find).and_return(@#{user_class})
      login
    end

    def do_delete
      delete :destroy, :id => @#{user_class}.id
    end

    it "should call destroy on the found user" do
      @#{user_class}.should_receive(:destroy).and_return(true) 
      do_delete
    end

    it "should redirect to the users list" do
      do_delete
      response.should redirect_to(new_#{user_class}_url)
    end
  end
end

  EOF
end

file("spec/models/user_spec.rb") do
  <<-EOF
require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe #{user_class.camelize} do
  before(:each) do
    @#{user_class} = valid_#{user_class}
  end

  it "should be valid" do
    @#{user_class}.should be_valid
  end

  context "signup" do
    before(:each) do
      @valid_attributes = {:email => "some@email.com",
                           :password => "password",
                           :password_confirmation => "password"}
    end

    it "should set email and passwords" do
      @#{user_class}.should_receive(:email=).with("some@email.com")
      @#{user_class}.should_receive(:password=).with("password")
      @#{user_class}.should_receive(:password_confirmation=).with("password")
      @#{user_class}.signup(@valid_attributes)
    end
    it "should save without session maintenance" do
      @#{user_class}.should_receive(:save_without_session_maintenance)
      @#{user_class}.signup(@valid_attributes)
    end
  end

end

  EOF
end

file("app/views/#{user_class.pluralize}/new.html.erb") do
  <<-EOF
<h1>Sign UP</h1>

<% af_form_for :#{user_class}, @#{user_class}, :url => #{user_class.pluralize}_path do |f| %>
  <%= f.error_messages %>
  <%= render :partial => "form", :object => f %>
  <%= f.submit "Sign Up" %>
<% end %>
  EOF
end

file("app/views/#{user_class.pluralize}/edit.html.erb") do
  <<-EOF
<h1>Edit My Account</h1>

<% af_form_for :#{user_class}, @#{user_class}, :url => #{user_class.pluralize}_path do |f| %>
  <%= f.error_messages %>
  <%= render :partial => "form", :object => f %>
  <%= f.submit "Update" %>
<% end %>
  EOF
end

file("app/views/#{user_class.pluralize}/_form.html.erb") do
  <<-EOF
<%= form.text_field :email %>
<%= form.password_field :password %>
<%= form.password_field :password_confirmation %>
  EOF
end
run("rm app/views/#{user_class.pluralize}/index.html.erb")

route "map.resources :#{user_class.pluralize}, :collection => {:activate => :get}"
route "map.root :controller => 'users', :action => 'new'"

generate :rspec_controller, "password_resets", "new", "edit"
route "map.resource :password_reset"

file('app/controllers/password_resets_controller.rb') do
  <<-EOF
class PasswordResetsController < ApplicationController
  before_filter :load_#{user_class}_using_perishable_token, :only => [:edit, :update]
  before_filter :require_no_#{user_class}

  def new
    @#{user_class} = #{user_class.camelize}.new
  end

  def create
    @#{user_class} = #{user_class.camelize}.find_by_email(params[:#{user_class}][:email])
    if @#{user_class}
      @#{user_class}.deliver_password_reset_instructions!
      add_notice "Instructions to reset your password have been emailed to you. Please check your email."
      redirect_to root_url
    else
      add_error "No #{user_class} was found with that email address"
      @#{user_class} = #{user_class.camelize}.new
      render :action => :new
    end
  end

  def edit

  end

  def update
    @#{user_class}.password = params[:#{user_class}][:password]
    @#{user_class}.password_confirmation = params[:#{user_class}][:password_confirmation]
    if @#{user_class}.save
      add_notice "Password successfully updated"
      redirect_to #{user_class}_path(@#{user_class})
    else
      add_error "Unable to update your password, try again."
      render :action => :edit
    end
  end

end

  EOF
end

file("app/views/password_resets/new.html.erb") do
  <<-EOF
<h1>Reset Your Password</h1>

<% af_form_for :#{user_class}, @#{user_class}, :url => password_reset_path do |f| %>
  <%= f.error_messages %>
  <%= f.text_field :email %>
  <%= f.submit "Reset Password" %>
<% end %>
  EOF
end

file("app/views/password_resets/edit.html.erb") do
  <<-EOF
<h1>Choose a new password</h1>

<% af_form_for :#{user_class}, @#{user_class},
               :url => password_reset_path(:id => @user.perishable_token),
               :html => { :method => :put } do |f| %>

  <%= f.error_messages %>
  <%= f.text_field :password %>
  <%= f.text_field :password_confirmation, :label => "Confirm Password" %>
  <%= f.submit "Change Password" %>
<% end %>
  EOF
end

file("spec/controllers/password_resets_controller_spec.rb") do
  <<-EOF
require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe PasswordResetsController do
  describe "handling POST /password_resets" do
    before(:each) do
      activate_authlogic
      @#{user_class} = valid_#{user_class}
      @#{user_class}.save
    end

    def do_post
      post :create, :#{user_class} => {:email => @#{user_class}.email}
    end

    context "if a #{user_class.camelize} exists" do
      before(:each) do
        #{user_class.camelize}.stub!(:find_by_email).and_return @#{user_class}
      end

      it "should send password reset instructions" do
        @#{user_class}.should_receive(:deliver_password_reset_instructions!)
        do_post
      end

      it "should redirect to root url" do
        do_post
        response.should redirect_to root_url
      end
    end

    context "if a #{user_class.camelize} doesn't exist" do
      before(:each) do
        #{user_class.camelize}.stub!(:find_by_email).and_return nil
      end

      it "should render new action" do
        do_post
        response.should render_template "new"
      end
    end

  end

  describe "handling PUT to /password_resets/" do
    before(:each) do
      @#{user_class} = valid_#{user_class}
      @#{user_class}.save
      #{user_class.camelize}.stub!(:find_using_perishable_token).and_return @#{user_class}
    end

    def do_put
      put :update, :#{user_class} => {:password => "password", :password_confirmation => "password"}
    end

    it "should update the #{user_class.pluralize} password" do
      @#{user_class}.should_receive(:password=).with('password')
      @#{user_class}.should_receive(:password_confirmation=).with('password')
      do_put
    end

    it "should redirect to #{user_class} url" do
      do_put
      response.should redirect_to(#{user_class}_url(@#{user_class}))
    end

  end
end

  EOF
end

file('app/models/notifier.rb') do
  <<-EOF
class Notifier < ActionMailer::Base
  default_url_options[:host] = ""

  def password_reset_instructions(user)
    subject       "Password Reset Instructions"
    from          "#{app_name} Notifier"
    recipients    user.email
    sent_on       Time.now
    body          :edit_password_reset_url => edit_password_reset_url(:id => user.perishable_token)
  end

  def activation_instructions(user)
    subject       "Activation Instructions"
    from          "#{app_name} Notifier"
    recipients    user.email
    sent_on       Time.now
    body          :account_activation_url => activate_users_url(:id => user.perishable_token)
  end

  def activation_confirmation(user)
    subject       "Activation Complete"
    from          "#{app_name} Notifier"
    recipients    user.email
    sent_on       Time.now
    body          :root_url => root_url
  end

end

  EOF
end

file("app/views/notifier/password_reset_instructions.erb") do
  <<-EOF
A request to reset your password has been made.  
If you did not make this request, simply ignore this email.  
If you did make this request just click the link below:  

<%= link_to "Reset Password", @edit_password_reset_url %>

If the above URL does not work try copying and pasting it into your browser.  
If you continue to have problem please feel free to contact us.
  EOF
end

file("app/views/notifier/activation_instructions.erb") do
  <<-EOF
Thank you for creating an account! Click the url below to activate your account!

<%= @account_activation_url %>

If the above URL does not work try copying and pasting it into your browser. If you continue to have problem, please feel free to contact us.

  EOF
end

file("app/views/notifier/activation_confirmation.erb") do
  <<-EOF
Your account has been activated.

<%= @root_url %>

If the above URL does not work try copying and pasting it into your browser. If you continue to have problem, please feel free to contact us.
  EOF
end

file("app/controllers/application_controller.rb") do
  <<-EOF
class ApplicationController < ActionController::Base
  filter_parameter_logging :password, :password_confirmation
  before_filter :activate_authlogic
  helper_method :current_#{session_class},
                :current_#{user_class},
                :require_#{user_class},
                :require_#{user_class},
                :load_#{user_class}_using_perishable_token,
                :redirect_back_or_default

  private
    def current_#{session_class}
      return @current_#{session_class} if defined?(@current_#{session_class})
      @current_#{session_class} = #{session_class.camelize}.find
    end

    def current_#{user_class}
      return @current_#{user_class} if defined?(@current_#{user_class})
      @current_user = current_#{session_class} && current_#{session_class}.#{user_class}
    end

    def require_#{user_class}
      unless current_#{user_class}
        store_location
        flash[:notice] = "You must be logged in to access this page"
        redirect_to new_#{session_class}_url
        return false
      end
    end

    def require_no_#{user_class}
      if current_#{user_class}
        store_location
        flash[:notice] = "You must be logged out to access this page"
        redirect_to user_path(current_user)
        return false
      end
    end

    def store_location
      session[:return_to] = request.request_uri
    end

    def redirect_back_or_default(default)
      redirect_to(session[:return_to] || default)
      session[:return_to] = nil
    end

    def load_#{user_class}_using_perishable_token
      @#{user_class} = #{user_class.camelize}.find_using_perishable_token(params[:id])
      unless @#{user_class}
        flash[:notice] = "We're sorry, but we could not locate your account. " +
        "If you are having issues try copying and pasting the URL " +
        "from your email into your browser."
        redirect_to root_url
      end
    end
end
  EOF
end
run("rm -rf spec/views/*")

rake "db:migrate"
git :add => "."
git :commit => "-m 'Adding Authlogic code'"

run("mkdir spec/support")
file("spec/support/fixjour_builders.rb") do
  <<-EOF
Fixjour do
  define_builder(#{user_class.camelize}) do |klass, overrides|
    klass.new
  end
end

include Fixjour
  EOF
end

file("spec/support/authlogic_helpers.rb") do
  <<-EOF
module AuthlogicHelperMethods

  def valid_user(overrides={})
    options = {:email => "valid@email.com", :password => "password", :password_confirmation => "password"}
    user = new_user(options)
  end

  def current_#{user_class}(stubs = {})
    @current_#{user_class} ||= valid_#{user_class}(stubs)
  end

  def current_#{session_class}(stubs = {}, #{user_class}_stubs = {})
    @current_#{session_class} ||= mock_model(#{session_class.camelize}, {:user => current_#{user_class}(#{user_class}_stubs)}.merge(stubs))
  end

  def login(#{session_class}_stubs = {}, #{user_class}_stubs = {})
    #{session_class.camelize}.stub!(:find).and_return(current_#{session_class}(#{session_class}_stubs, #{user_class}_stubs))
  end

  def logout
    @#{session_class} = nil
  end

end
  EOF
end

file("spec/spec_helper.rb") do
  <<-EOF
# This file is copied to ~/spec when you run 'ruby script/generate rspec'
# from the project root directory.
ENV["RAILS_ENV"] = "test"
require File.expand_path(File.dirname(__FILE__) + "/../config/environment")
require 'spec/autorun'
require 'spec/rails'
Dir[File.dirname(__FILE__) + "/support/**/*.rb"].each {|f| require f}
require 'authlogic/test_case'

Spec::Runner.configure do |config|
  config.use_transactional_fixtures = true
  config.use_instantiated_fixtures  = false
  config.fixture_path = RAILS_ROOT + '/spec/fixtures/'

  config.include(Fixjour)
  config.include(AuthlogicHelperMethods)
end

  EOF
end

git :add => "."
git :commit => "-m 'Adding test builders and helpers'"

file("features/authentication.feature") do
  <<-EOF
Feature: Authenication
  In order to have people use my application
  As a developer
  I want to provide sign up, login, activation and password resetting

  Scenario: Signing Up
    Given I am on new_user
    And I am a new user
    When I fill in "user[email]" with "some@email.com"
    And I fill in "user[password]" with "password"
    And I fill in "user[password_confirmation]" with "password"
    And I press "Sign Up"
    Then I should see "Your account has been created. Please check your e-mail for your account activation instructions!"
    And I should be on new_user_session
    When I open the email
    And I click the first link in the email
    Then I should be on the login page

  Scenario: Logging In
    Given I am an existing user
    And I am on new_user_session
    When I fill in "user_session[email]" with "valid@email.com"
    And I fill in "user_session[password]" with "password"
    And I press "Login"
    Then I should be on my account page

  Scenario: Scenario: Resetting my password
    Given I am an existing user
    And I am on new_password_reset
    When I fill in "user[email]" with "valid@email.com"
    And I press "Reset Password"
    Then I should see "Instructions"
    When I open the email
    And I click the first link in the email
    And I fill in "Password" with "soccer"
    And I fill in "Confirm Password" with "soccer"
    And I press "Change Password"
    Then I should be on my account page
    And I should see "Password successfully updated"

  EOF
end

file("features/step_definitions/authentication_steps.rb") do
  <<-EOF
Given /^I am an existing user$/ do
  @user = valid_user(:email => "valid@email.com", :password => "password", :password_confirmation => "password")
  @user.save
  @user.activate!
end

Given /^I am a new user$/ do
  @user = new_user(:email => "some@email.com") 
end

Given /^I requested a password reset$/ do
  @user.reset_perishable_token!
end

  EOF
end

file("features/support/env.rb") do
  <<-EOF
# Sets up the Rails environment for Cucumber
ENV["RAILS_ENV"] ||= "cucumber"
require File.expand_path(File.dirname(__FILE__) + '/../../config/environment')
require 'cucumber/rails/world'

# Comment out the next line if you don't want Cucumber Unicode support
require 'cucumber/formatter/unicode'

# Comment out the next line if you don't want transactions to
# open/roll back around each scenario
Cucumber::Rails.use_transactional_fixtures

# Comment out the next line if you want Rails' own error handling
# (e.g. rescue_action_in_public / rescue_responses / rescue_from)
Cucumber::Rails.bypass_rescue

require 'webrat'

Webrat.configure do |config|
  config.mode = :rails
end

require 'cucumber/rails/rspec'
require 'webrat/core/matchers'
require 'email_spec/cucumber'

require File.expand_path(File.dirname(__FILE__) +'/../../spec/support/fixjour_builders.rb')
World(Fixjour)
require File.expand_path(File.dirname(__FILE__) +'/../../spec/support/authlogic_helpers.rb')
World(AuthlogicHelperMethods)

  EOF
end

file("features/support/paths.rb") do
%q{
  module NavigationHelpers
   def path_to(page_name)
     case page_name

       when /the homepage/
         '/'
       when /my account page/
         user_path(User.last.id)
       when /new_user_session/
         new_user_session_path()
       when /my password reset page/
         edit_password_reset_path(:id => User.last.perishable_token)
       when /the login page/
         new_user_session_path

       else
         begin
           eval(page_name+'_path')
         rescue
           raise "Can't find mapping from \"#{page_name}\" to a path.\n" +
                   "Now, go and add a mapping in #{__FILE__}"
         end
     end
   end
  end

  World(NavigationHelpers)

}
end

file("features/step_definitions/utility_steps.rb") do
  <<-EOF
Then /^I save and open page$/ do
  save_and_open_page
end

  EOF
end

generate "email_spec"

git :add => "."
git :commit => "-m 'Cucumber features for authentication'"

footer = <<-FOOTER

###################################
# Rails App Template by the science department (BJ Clark)
# http://www.scidept.com && http://bjclark.me
# 
# Features: Full BDD suite with working specs and features. JQuery. Authlogic with activation and password recovery. Custom form builder, just include css file into layour for full effect. Resource_Controller for sahara worthy controllers.
# 
# Last Steps:
# 1. Set up any acl you would like in your controllers. Check out the Authlogic tutorials for examples.
# 2. Edit the url host name in Notifier.rb or your emails won't work.
# 3. Edit the #current_email_address method in features/step_definitions/email_steps.rb
# 4. rake spec && rake features
# 5. Profit!
###################################

FOOTER

puts footer
