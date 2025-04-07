# frozen_string_literal: true

require 'debug'
require 'optparse'

task :routes, [:dir] do |task, args|
  require 'action_controller'

  options = {}
  opts = OptionParser.new
  opts.banner = "Usage: rake routes [directory]"
  opts.on("-d", "--dir ARG", String) { |dir| options[:dir] = dir }
  args = opts.order!(ARGV) {}
  opts.parse!(args)

  case options[:dir]
  when 'oauth'
    # run with rake routes -- -d 'oauth'
    require_relative './oauth/server'
  else
    raise 'unrecognized server'
  end

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
