module Garrison
  module Checks
    class CheckEngineVersion < Check

      def settings
        self.source ||= 'aws-rds'
        self.severity ||= 'low'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
        self.options[:engines] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'rds' },
          { key: 'aws-account', value: AwsHelper.whoami }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"

          if ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN']
            role_credentials = Aws::AssumeRoleCredentials.new(
              client: Aws::STS::Client.new(region: region),
              role_arn: ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN'],
              role_session_name: 'garrison-agent-rds'
            )

            rds = Aws::RDS::Client.new(credentials: role_credentials, region: region)
          else
            rds = Aws::RDS::Client.new(region: region)
          end

          versions = versions_rds(rds).select { |i| i[:newer_versions].any? }

          versions.each do |database|
            target = database[:instance].db_instance_identifier

            alert(
              name: 'Database Out of Date',
              target: target,
              detail: "engine_version: #{database[:instance].engine_version} < #{database[:newer_versions].map(&:to_s).join(', ')}",
              finding: {
                newer_versions: database[:newer_versions],
                instance: database[:instance].to_h
              }.to_json,
              finding_id: "aws-rds-#{target}-dbv_#{database[:instance].engine_version}",
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/rds/home?region=#{region}#dbinstance:id=#{target}"
                }
              ],
              key_values: [
                {
                  key: 'aws-region',
                  value: region
                }
              ]
            )
          end
        end
      end

      private

      def versions_rds(rds)
        Logging.debug 'AWS SDK - Pulling all RDS instance metadata'
        db_instances = rds.describe_db_instances.db_instances
        return [] if db_instances.empty?

        engines_and_versions = AwsHelper.available_engines_and_versions(rds)

        if options[:engines] && options[:engines] != 'all'
          db_instances.select! { |i| options[:engines].include?(i.engine) }
        end

        # aurora instances don't report their engine specifically enough to match
        # against the available versions returned by the api as of 2018-06-14
        db_instances.reject! { |instance| instance.engine == 'aurora' }

        db_instances.map do |instance|
          instance_version = Mixlib::Versioning.parse(instance.engine_version)
          engine_versions = engines_and_versions[instance.engine]

          {
            instance: instance,
            newer_versions: engine_versions.select { |version| version > instance_version }
          }
        end

      rescue Aws::RDS::Errors::OptInRequired => e
        Logging.warn "#{region} - #{e.message}"
        return []
      rescue Aws::RDS::Errors::InvalidClientTokenId => e
        Logging.warn "#{region} - #{e.message}"
        return []
      end
    end
  end
end
