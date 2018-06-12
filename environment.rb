require 'bundler'
Bundler.require(:default)
ROOT = File.dirname(__FILE__)

Dir[File.join(ROOT, 'lib', '*.rb')].each do |file|
  require file
end

@logger.info('Garrison Agent - AWS RDS')

REGIONS = ENV['GARRISON_AWS_REGIONS'] ? ENV['GARRISON_AWS_REGIONS'].split(',') : Aws.partition('aws').regions.map(&:name)
url     = ENV['GARRISON_URL']

Garrison::Api.configure do |config|
  config.url = url
end
