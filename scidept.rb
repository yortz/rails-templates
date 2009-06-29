run "echo TODO > README"

gem 'dchelimsky-rspec', :source => "http://gems.github.com", :lib => "spec", :version => "1.2.7"
gem 'dchelimsky-rspec-rails', :source => "http://gems.github.com", :lib => "spec/rails", :version => "1.2.7"
gem 'aslakhellesoy-cucumber', :source => "http://gems.github.com", :lib => "cucumber", :version => "0.3.11.6"
gem 'webrat', :version => "0.4.4"
gem 'nakajima-fixjour', :source => "http://gems.github.com", :lib => "fixjour", :version => "0.2.0"
gem "bmabey-email_spec", :source => "http://gems.github.com", :lib => "email_spec", :version => "0.3.0"

gem 'binarylogic-authlogic', :lib => "authlogic", :source => 'http://gems.github.com', :verson => "2.1.0"
gem "giraffesoft-resource_controller", :source => "http://gems.github.com", :lib => "resource_controller", :version => "0.6.5"
gem 'less', :version => "0.7.0"
gem "newrelic_rpm"

rake "gems:install"

plugin "less-for-rails", :git => "git://github.com/augustl/less-for-rails.git"

run 'rm public/javascripts/*'
plugin "jrails", :git => "git://github.com/aaronchi/jrails.git"

plugin "accessible_form_builder", :git => "git://github.com/BJClark/accessible_form_builder.git"
plugin "flash-message-conductor", :git => "git://github.com/planetargon/flash-message-conductor.git"

generate :rspec
generate :cucumber

run "rm public/index.html"

run "git clone git://github.com/davemerwin/960-grid-system.git"
run "mkdir public/stylesheets/960gs"
run "cp 960-grid-system/code/css/*.css public/stylesheets/960gs"
run "rm -rf 960-grid-system"
run "touch public/stylesheets/screen.less"
run "touch public/stylesheets/print.less"

run "mkdir assets"

run "rm -rf test"

git :init

file ".gitignore", <<-END
.DS_Store
log/*.log
tmp/**/*
config/database.yml
assets/*
.idea
.generators
END

run "touch tmp/.gitignore log/.gitignore vendor/.gitignore"
run "cp config/database.yml config/example_database.yml"

git :add => "."
git :commit => "-m 'Initial commit'"

run "createuser -s #{self.root}"
rake "db:create"

session_class = ask("Hello, what should I call your session model (ex 'user_session')?")

generate :session, session_class
generate :scaffold_resource, session_class, "-s", "--skip-migration"

file("app/views/#{session_class}/new.html.erb") do
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

file("app/controllers/#{session_class}_controller.rb") do
  <<-EOF
class #{session_class.capitalize}Controller < ResourceController::Singleton
end
  EOF
end

route "map.resource :#{session_class}"


user_class = ask("Hello, what should I call your 'user' model (ex 'user')?")

generate :scaffold_resource, user_class, "email:string", "crypted_password:string", "password_salt:string", "persistence_token:string", "single_access_token:string", "perishable_token:string", "last_login_at:datetime", "active:boolean"

file("app/models/#{user_class}.rb") do
  <<-EOF
class User < ActiveRecord::Base
  attr_accessible :email, :password, :password_confirmation
  
  acts_as_authentic

  def activate!
   self.active = true
   save
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
  before_filter :load_user_using_perishable_token, :only => [:activate]
  before_filter :require_user, :only => [:index]

  def create
    @#{user_class} = #{user_class.camelize}.new

    if @#{user_class}.signup(params[:#{user_class}])
      @#{user_class}.deliver_activation_instructions!
      flash[:notice] = "Your account has been created. Please check your e-mail for your account activation instructions!"
      redirect_to root_url
    else
      render :action => :new
    end
  end

  def activate
    if @#{user_class}.activate!
      @#{user_class}.deliver_activation_confirmation!
      flash[:notice] = "Your account has been activated."
      redirect_to account_url
    else
      flash[:error] = "Unable to active your account, please try again. If this error persists, contact support."
      render :action => :new
    end
  end

end
  EOF
end

file("spec/controllers/users_controller_spec.rb") do
  <<-EOF
require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe #{user_class.camelize.pluralize}Controller do
  before(:each) { activate_authlogic }

  describe "handling GET /#{user_class.pluralize}/new" do

    before(:each) do
      @#{user_class} = valid_#{user_class}
      #{user_class.camelize}.stub!(:new).and_return(@#{user_class})
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

      it "should redirect to the new #{user_class}" do
        do_post
        response.should redirect_to(root_url)
      end

      it "should deliver activation instructions" do
        @#{user_class}.should_receive(:deliver_activation_instructions!)
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
      @user = valid_#{user_class}(:id => 1)
      #{user_class.camelize}.stub!(:find).and_return(@#{user_class})
    end

    def do_delete
      delete :destroy, :id => "1"
    end

    it "should find the #{user_class} requested" do
      #{user_class.camelize}.should_receive(:find).with("1").and_return(@#{user_class})
      do_delete
    end

    it "should call destroy on the found user" do
      @#{user_class}.should_receive(:destroy).and_return(true) 
      do_delete
    end

    it "should redirect to the users list" do
      do_delete
      response.should redirect_to(#{user_class.pluralize}_url)
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

<% af_form_for @#{user_class}, :url => account_path do |f| %>
  <%= f.error_messages %>
  <%= render :partial => "form", :object => f %>
  <%= f.submit "Sign Up" %>
<% end %>
  EOF
end

file("app/views/#{user_class.pluralize}/edit.html.erb") do
  <<-EOF
<h1>Edit My Account</h1>

<% form_for @#{user_class}, :url => account_path do |f| %>
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

route "map.resource :account, :controller => '#{user_class.pluralize}'"
route "map.resources :users, :collection => {:activate => :get}"
route "map.root :controller => 'users', :action => 'new'"

generate :rspec_controller, "password_resets", "new", "create"
route "map.resource :password_resets"

file('app/controllers/password_resets_controller.rb') do
  <<-EOF
class PasswordResetsController < ApplicationController
  before_filter :load_user_using_perishable_token, :only => [:edit, :update]
  before_filter :require_no_user

  def new

  end

  def create
    @#{user_class} = #{user_class.capitalize}.find_by_email(params[:email])
    if @#{user_class}
      @#{user_class}.deliver_password_reset_instructions!
      flash[:notice] = "Instructions to reset your password have been emailed to you. Please check your email."
      redirect_to root_url
    else
      flash[:notice] = "No #{user_class} was found with that email address"
      render :action => :new
    end
  end

  def edit

  end

  def update
    @user.password = params[:user][:password]
    @user.password_confirmation = params[:user][:password_confirmation]
    if @user.save
      flash[:notice] = "Password successfully updated"
      redirect_to account_url
    else
      render :action => :edit
    end
  end

end

  EOF
end

file("spec/controllers/password_resets_controller.rb") do
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

    context "#{user_class.camelize} exists" do
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

    context "#{user_class.camelize} doesn't exist" do
      before(:each) do
        #{user_class.camelize}.stub!(:find_by_email).and_return nil
      end

      it "should redirect to new action" do
        do_post
        response.should redirect_to :action => "new"
      end
    end

  end

  describe "handling POST to /password_resets/" do
    before(:each) do
      #{user_class.camelize}.stub!(:find_by_perishable_token).and_return @#{user_class}
    end

    def do_put
      put :update, :#{user_class} => {:password => "password", :password_confirmation => "password"}
    end

    it "should update the #{user_class.pluralize} password" do
      @#{user_class}.should_receive(:password=).with('password')
      do_put
    end
    it "should redirect to account_url" do
      do_put
      response.should redirect_to(account_url)
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
    from          "#{self.root.capitalize} Notifier"
    recipients    user.email
    sent_on       Time.now
    body          :edit_password_reset_url => edit_password_reset_url(user.perishable_token)
  end

  def activation_instructions(user)
    subject       "Activation Instructions"
    from          "#{self.root.capitalize} Notifier"
    recipients    user.email
    sent_on       Time.now
    body          :account_activation_url => activate_users_url(user.perishable_token)
  end

  def activation_confirmation(user)
    subject       "Activation Complete"
    from          "#{self.root.capitalize} Notifier"
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
                :load_user_using_perishable_token,
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
        redirect_to account_url
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

    def load_user_using_perishable_token
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
  define_builder(#{user_class.capitalize}) do |klass, overrides|
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
    #{session_class.camelize}.stub!(:find).and_return(#{user_class}_session(#{session_class}_stubs, #{user_class}_stubs))
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
# 3. rake spec && rake features
# 4. Profit!
###################################

FOOTER

puts footer
