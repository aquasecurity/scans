var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Forecast Dataset Encrypted',
    category: 'AI & ML',
    owasp: ['LLM04', 'LLM02'],
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensure that AWS Forecast datasets are using desired KMS key for data encryption.',
    more_info: 'Datasets contain the data used to train a predictor. You create one or more Amazon Forecast datasets and import your training data into them. ' +
               'Make sure to enable encryption for these datasets using customer-managed keys (CMKs) in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create Forecast datasets using customer-manager KMS keys (CMKs).',
    link: 'https://docs.aws.amazon.com/forecast/latest/dg/API_CreateDataset.html',
    apis: ['ForecastService:listDatasets', 'ForecastService:describeDataset', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        forecast_dataset_desired_encryption_level: {
            name: 'Forecast Dataset Desired Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },
    realtime_triggers: ['forecastservice:CreateDataset', 'forecastservice:DeleteDataset'],


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
            var listDatasets = helpers.addSource(cache, source,
                ['forecastservice', 'listDatasets', region]);

            if (!listDatasets) return rcb();

            if (listDatasets.err || !listDatasets.data) {
                helpers.addResult(results, 3, `Unable to query Forecast datasets: ${helpers.addError(listDatasets)}`, region);
                return rcb();
            }

            if (!listDatasets.data.length) {
                helpers.addResult(results, 0, 'No Forecast datasets found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let dataset of listDatasets.data) {
                if (!dataset.DatasetArn) continue;

                let resource = dataset.DatasetArn;

                let describeDataset = helpers.addSource(cache, source,
                    ['forecastservice', 'describeDataset', region, resource]);

                if (!describeDataset || describeDataset.err || !describeDataset.data) {
                    helpers.addResult(results, 3,
                        `Unable to query Forecast dataset: ${helpers.addError(describeDataset)}`, region, resource);
                    continue;
                }

                if (describeDataset.data.EncryptionConfig &&
                    describeDataset.data.EncryptionConfig.KMSKeyArn) {
                    let kmsKey = describeDataset.data.EncryptionConfig.KMSKeyArn;
                    let kmsKeyId = kmsKey.split('/')[1] ? kmsKey.split('/')[1] : kmsKey;

                    let describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);  
    
                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKey);
                        continue;
                    }
    
                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Forecast dataset is encrypted with ${currentEncryptionLevelString} \
                                which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Forecast dataset is encrypted with ${currentEncryptionLevelString} \
                                which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Forecast dataset does not have encryption enabled', region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};