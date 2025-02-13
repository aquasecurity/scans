var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Model Data Encrypted',
    category: 'AI & ML',
    owasp: ['LLM10', 'LLM04', 'LLM02'],
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensure that Lookout for Vision model data is encrypted using desired KMS encryption level',
    more_info: 'By default, trained models and manifest files are encrypted in Amazon S3 using server-side encryption with KMS keys stored in AWS Key Management Service (SSE-KMS). ' +
        'You can also use customer-managed keys instead in order to gain more granular control over encryption/decryption process.',
    link: 'https://docs.aws.amazon.com/lookout-for-vision/latest/developer-guide/security-data-encryption.html',
    recommended_action: 'Encrypt LookoutVision model with customer-manager keys (CMKs) present in your account',
    apis: ['LookoutVision:listProjects', 'LookoutVision:listModels', 'LookoutVision:describeModel', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        model_data_desired_encryption_level: {
            name: 'Vision Data Target Encryption Level',
            description: 'In order (lowest to highest) sse=S3-SSE; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms'
        }
    },
    realtime_triggers: ['lookoutvision:CreateModel', 'lookoutvision:DeleteModel'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.model_data_desired_encryption_level || this.settings.model_data_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(region.lookoutvision, function(region, rcb){
            var listProjects = helpers.addSource(cache, source,
                ['lookoutvision', 'listProjects', region]);

            if (!listProjects) return rcb();

            if (listProjects.err || !listProjects.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Lookout for Vision projects: ' + helpers.addError(listProjects), region);
                return rcb();
            }

            if (!listProjects.data.length) {
                helpers.addResult(results, 0, 'No Lookout for Vision projects found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            for (let project of listProjects.data){
                if (!project.ProjectName) continue;

                let projectArn = project.ProjectArn;

                var listModels = helpers.addSource(cache, source,
                    ['lookoutvision', 'listModels', region, project.ProjectName]);

                if (!listModels || listModels.err || !listModels.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Lookout for Vision models: ' + project.ProjectName + ': ' + helpers.addError(listModels),
                        region, projectArn);
                    continue;
                }

                if (!listModels.data.Models || !listModels.data.Models.length) {
                    helpers.addResult(results, 0,
                        'No models found for Lookout for Vision project',
                        region, projectArn);
                    continue;
                }

                for (let model of listModels.data.Models) {
                    if (!model.ModelArn) continue;

                    let resource = model.ModelArn;

                    var describeModel = helpers.addSource(cache, source,
                        ['lookoutvision', 'describeModel', region, model.ModelArn]);

                    if (!describeModel ||
                        describeModel.err ||
                        !describeModel.data || !describeModel.data.ModelDescription) {
                        helpers.addResult(results, 3,
                            'Unable to get Lookout for Vision models: ' + helpers.addError(describeModel), region, resource);
                        continue;
                    }

                    if (describeModel.data.ModelDescription.KmsKeyId) {
                        let kmsKey =  describeModel.data.ModelDescription.KmsKeyId;
                        let keyId = kmsKey.split('/')[1] ? kmsKey.split('/')[1] : kmsKey;

                        let describeKey = helpers.addSource(cache, source,
                            ['kms', 'describeKey', region, keyId]);

                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                            helpers.addResult(results, 3,
                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                region, kmsKey);
                            continue;
                        }

                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);

                    } else {
                        currentEncryptionLevel = 1; //sse
                    }

                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Model data is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Model data is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
