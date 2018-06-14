module Garrison
  module Agents
    class Check

      attr_accessor :severity
      attr_accessor :family
      attr_accessor :type
      attr_accessor :options

      def initialize(options = {})
        @severity = ENV['GARRISON_ALERT_SEVERITY']
        @type     = ENV['GARRISON_ALERT_TYPE']
        @family   = ENV['GARRISON_ALERT_FAMILY']
        @options  = options

        Logging.info "Starting... #{self.class.name}"
        inherit_settings
        Logging.info "Agent Settings (severity=#{self.severity} type=#{self.type} family=#{self.family})"

        options_log = options.map do |key, value|
          value = value.is_a?(Array) ? value.join(',') : value
          "#{key}=#{value}"
        end
        Logging.info "Check Settings (#{options_log.join(' ')})" if options.any?
      end

      def perform
        raise 'You must override this method'
      end

      def alert(name:, target:, detail:, finding:, finding_id:, urls: [], key_values: [])
        Logging.info "Raising alert for '#{target}'"

        alert = Api::Alert.new
        alert.type = type
        alert.family = family
        alert.source = 'aws-rds'

        alert.name = name
        alert.target = target
        alert.detail = detail
        alert.severity = severity

        alert.finding = finding
        alert.finding_id = finding_id
        alert.detected_at = Time.now.utc

        alert.urls = urls

        alert.key_values = key_values
        alert.key_values << { key: 'datacenter', value: 'aws' }
        alert.key_values << { key: 'aws-service', value: 'rds' }
        alert.key_values << { key: 'aws-account', value: AwsHelper.whoami.account }

        alert.save
      end

      private

      def inherit_settings
        settings
      end
    end
  end
end
