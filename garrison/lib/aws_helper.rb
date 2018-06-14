module Garrison
  class AwsHelper

    def self.all_regions
      Aws.partition('aws').regions.map(&:name)
    end

    def self.available_engines_and_versions(rds)
      Logging.debug 'AWS SDK - Pulling all supported engines and versions'
      db_engine_versions = describe_db_engine_versions(rds)

      db_engine_versions.each_with_object({}) do |engine_and_version, hash|
        hash[engine_and_version.engine] ||= []
        hash[engine_and_version.engine] << Mixlib::Versioning.parse(engine_and_version.engine_version)
      end
    end

    private

    def self.describe_db_engine_versions(rds)
      Enumerator.new do |yielder|
        marker = ''

        loop do
          results = rds.describe_db_engine_versions(marker: marker)
          results.db_engine_versions.map { |item| yielder << item }

          if results.marker
            marker = results.marker
          else
            raise StopIteration
          end
        end
      end.lazy
    end

  end
end
