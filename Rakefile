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

  # case options[:dir]
  # when 'oauth'
  #   # run with rake routes -- -d 'oauth'
  #   require_relative './app/server'
  # else
  #   raise 'unrecognized server'
  # end
  require_relative 'app/server'

  inspector = ActionDispatch::Routing::RoutesInspector.new(Rails.application.routes.routes)
  formatter = ActionDispatch::Routing::ConsoleFormatter::Sheet.new

  puts inspector.format(formatter, {})
end
