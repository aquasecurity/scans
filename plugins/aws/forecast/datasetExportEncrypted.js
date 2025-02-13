var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Forecast Dataset Export Encrypted',
    category: 'AI & ML',
    owasp: ['LLM02'],
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensure that AWS Forecast exports have encryption enabled before they are being saved on S3.',
    more_info: 'In AWS Forecast, you can save forecast reports on S3 in CSV format. Make sure to encrypt these export before writing them to the bucket in order to follow your organizations\'s security and compliance requirements.',
    recommended_action: 'Create Forecast exports with encryption enabled',
    link: 'https://docs.aws.amazon.com/forecast/latest/dg/howitworks-forecast.html',
    apis: ['ForecastService:listForecastExportJobs', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        forecast_dataset_desired_encryption_level: {
            name: 'Forecast Dataset Desired Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },
    realtime_triggers: ['forecast:CreateForecastExportJob', 'forecast:DeleteForecastExportjob'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.forecast_dataset_desired_encryption_level || this.settings.forecast_dataset_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.forecastservice, function(region, rcb){
            var listForecastExportJobs = helpers.addSource(cache, source,
                ['forecastservice', 'listForecastExportJobs', region]);

            if (!listForecastExportJobs) return rcb();

            if (listForecastExportJobs.err || !listForecastExportJobs.data) {
                helpers.addResult(results, 3,
                    'Unable to query Forecast exports: ' + helpers.addError(listForecastExportJobs), region);
                return rcb();
            }

            if (!listForecastExportJobs.data.length) {
                helpers.addResult(results, 0, 'No Forecast exports found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let forecastExportJob of listForecastExportJobs.data) {
                if (!forecastExportJob.Destination) {
                    continue;
                }

                let { S3Config } = forecastExportJob.Destination;
                let resource = forecastExportJob.ForecastExportJobArn;

                if (S3Config && S3Config.KMSKeyArn) {
                    let encryptionKey = S3Config.KMSKeyArn;
                    var keyId = encryptionKey.split('/')[1] ? encryptionKey.split('/')[1] : encryptionKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, encryptionKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Forecast dataset export is encrypted with ${currentEncryptionLevelString} \
                                which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Forecast dataset export is encrypted with ${currentEncryptionLevelString} \
                                which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Forecast dataset export does not have encryption enabled', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
