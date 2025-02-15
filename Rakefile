# frozen_string_literal: true

require 'debug'
require 'optparse'

task :routes do
  require_relative './auth_server'
  require 'action_dispatch/routing/inspector'

  inspector = ActionDispatch::Routing::RoutesInspector.new(Rails.application.routes.routes)
  formatter = ActionDispatch::Routing::ConsoleFormatter::Sheet.new

  puts inspector.format(formatter, {})
end

require 'minitest/test_task'

# to run a specific test:
# N=/regexoftest/ rake test
Minitest::TestTask.create(:test) do |t|
  t.warning = false
  t.test_globs = ['**/*_test.rb']
end
