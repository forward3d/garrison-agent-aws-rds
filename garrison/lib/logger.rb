require 'logger'

module Garrison
  module Logging
    class << self
      def logger
        @logger ||= Logger.new($stdout)
      end

      def logger=(logger)
        @logger = logger
      end

      levels = %w[debug info warn error fatal]
      levels.each do |level|
        define_method(level.to_sym) do |msg|
          logger.send(level, msg)
        end
      end
    end
  end
end
