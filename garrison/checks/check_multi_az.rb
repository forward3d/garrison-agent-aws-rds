module Garrison
  module Checks
    class CheckMultiAz < Check

      def settings
        self.source ||= 'aws-rds'
        self.severity ||= 'medium'
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
          not_multi_az = single_zone_rds(region)

          not_multi_az.each do |instance|
            alert(
              name: 'Availability Violation',
              target: instance.db_instance_identifier,
              detail: 'multi_az: false',
              finding: instance.to_h.to_json,
              finding_id: "aws-rds-#{instance.db_instance_identifier}-multi_az",
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/rds/home?region=#{region}#dbinstance:id=#{instance.db_instance_identifier}"
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

      def single_zone_rds(region)
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

        db_instances = rds.describe_db_instances.db_instances

        # aurora & docdb instances don't have the multi_az flag, it always returns false
        db_instances.reject! { |instance| instance.engine == 'aurora' }
        db_instances.reject! { |instance| instance.engine == 'docdb' }

        # don't include read replicas
        db_instances.select! { |i| i.read_replica_source_db_instance_identifier.nil? }

        if options[:engines] && options[:engines] != 'all'
          db_instances.select! { |i| options[:engines].include?(i.engine) }
        end

        db_instances.select { |i| i.multi_az == false }
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
