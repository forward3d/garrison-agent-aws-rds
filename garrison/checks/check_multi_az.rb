module Garrison
  module Checks
    class CheckMultiAz < Check

      def settings
        self.severity ||= 'medium'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
        self.options[:engines] ||= 'all'
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
        rds = Aws::RDS::Client.new(region: region)
        db_instances = rds.describe_db_instances.db_instances

        # aurora instances don't honor the multi_az flag, it always returns false
        db_instances.reject! { |instance| instance.engine == 'aurora' }

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
