var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Custom Model Encryption Enabled',
    category: 'AI & ML',
    owasp: ['LLM10'],
    domain: 'Machine Learning',
    severity: 'High',
    description: 'Ensure that an Amazon Bedrock custom models are encrypted with desired encryption level.',
    more_info: 'When you encrypt AWS Bedrock custom model using your own AWS Customer Managed Keys (CMKs) for enhanced protection, you have full control over who can use the encryption keys to access your custom model.',
    recommended_action: 'Encrypt Bedrock custom model with desired encryption level.',
    link: 'https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html',
    apis: ['Bedrock:listCustomModels', 'Bedrock:getCustomModel', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        bedrock_model_desired_encryption_level: {
            name: 'Bedrock Custom Model Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var config = {
            desiredEncryptionLevelString: settings.bedrock_model_desired_encryption_level || this.settings.bedrock_model_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);

        async.each(regions.bedrock, function(region, rcb){
            var listCustomModels = helpers.addSource(cache, source,
                ['bedrock', 'listCustomModels', region]);

            if (!listCustomModels) return rcb();

            if (listCustomModels.err && listCustomModels.err.message.includes('Unknown operation')) {
                helpers.addResult(results, 0,
                    'Custom model service is not available in this region', region);
                return rcb();
            }

            if (listCustomModels.err || !listCustomModels.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Bedrock custom model list: ${helpers.addError(listCustomModels)}`, region);
                return rcb();
            }

            if (!listCustomModels.data.length) {
                helpers.addResult(results, 0, 'No Bedrock custom model found', region);
                return rcb();
            }
            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let model of listCustomModels.data) {
                if (!model.modelArn) continue;
               
                let resource = model.modelArn;

                let getCustomModel = helpers.addSource(cache, source,
                    ['bedrock', 'getCustomModel', region, model.modelName]);

    
                if (!getCustomModel || getCustomModel.err || !getCustomModel.data) {
                    helpers.addResult(results, 3, `Unable to describe Bedrock custom model : ${helpers.addError(getCustomModel)}`, region, resource);
                    continue;
                }

                let currentEncryptionLevel = 2;

                if (getCustomModel.data.modelKmsKeyArn) {
                    var kmsKeyId = getCustomModel.data.modelKmsKeyArn.split('/')[1] ? getCustomModel.data.modelKmsKeyArn.split('/')[1] : getCustomModel.data.modelKmsKeyArn;
    
                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);  
                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, getCustomModel.data.modelKmsKeyArn);
                        continue;
                    }
                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    
                }
                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Bedrock Custom model is encrypted with ${currentEncryptionLevelString} 
                                which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Bedrock Custom model is encrypted with ${currentEncryptionLevelString} 
                                which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                }
                
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};