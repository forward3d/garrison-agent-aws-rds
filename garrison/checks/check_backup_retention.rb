module Garrison
  module Checks
    class CheckBackupRetention < Check

      def settings
        self.source ||= 'aws-rds'
        self.severity ||= 'high'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
        self.options[:engines] ||= 'all'
        self.options[:threshold] ||= 7
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
          no_backups = no_backup_rds(region)

          no_backups.each do |instance|
            alert(
              name: 'Backup Violation',
              target: instance.db_instance_identifier,
              detail: "backup_retention_period: #{instance.backup_retention_period} (<#{options[:threshold]})",
              finding: instance.to_h.to_json,
              finding_id: "aws-rds-#{instance.db_instance_identifier}-backup_retention",
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

      def no_backup_rds(region)
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

        if options[:engines] && options[:engines] != 'all'
          db_instances.select! { |i| options[:engines].include?(i.engine) }
        end

        # don't include read replicas
        db_instances.select! { |i| i.read_replica_source_db_instance_identifier.nil? }

        db_instances.select { |i| i.backup_retention_period < options[:threshold].to_i }
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
