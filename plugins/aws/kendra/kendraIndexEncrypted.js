var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Kendra Index Encrypted',
    category: 'AI & ML',
    owasp: ['LLM02'],
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that the Kendra index is encrypted using desired encryption level.',
    more_info: 'Amazon Kendra encrypts your data at rest with AWS-manager keys by default. Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create Kendra Index with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/kendra/latest/dg/encryption-at-rest.html',
    apis: ['Kendra:listIndices','Kendra:describeIndex', 'KMS:describeKey', 'KMS:listKeys', 'STS:getCallerIdentity'],
    settings: {
        kendra_index_desired_encryption_level: {
            name: 'Kendra Index Encrypted',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms'
        }
    },
    realtime_triggers: ['kendra:CreateIndex','kendra:UpdateIndex','kendra:DeleteIndex'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.kendra_index_desired_encryption_level || this.settings.kendra_index_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.kendra, function(region, rcb){        
            var listIndices = helpers.addSource(cache, source,
                ['kendra', 'listIndices', region]);
                
            if (!listIndices) return rcb();

            if (listIndices.err || !listIndices.data) {
                helpers.addResult(results, 3,
                    'Unable to query Kendra Indices: ' + helpers.addError(listIndices), region);
                return rcb();
            }

            if (!listIndices.data.length) {
                helpers.addResult(results, 0, 'No Kendra Indices found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let index of listIndices.data) {
                var resource = `arn:${awsOrGov}:kendra:${region}:${accountId}:index/${index.Name}`;

                var describeIndex = helpers.addSource(cache, source,
                    ['kendra', 'describeIndex', region, index.Id]);
                    
                if (!describeIndex || describeIndex.err || !describeIndex.data ) {
                    helpers.addResult(results, 3,
                        `Unable to get Kendra index description: ${helpers.addError(describeIndex)}`,
                        region, resource);
                    continue;
                } 

                if (describeIndex.data.ServerSideEncryptionConfiguration &&
                    describeIndex.data.ServerSideEncryptionConfiguration.KmsKeyId) {
                    var kmsKeyId = describeIndex.data.ServerSideEncryptionConfiguration.KmsKeyId;
                    var keyId = kmsKeyId.split('/')[1] ? kmsKeyId.split('/')[1] : kmsKeyId;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, keyId]);  
                        
                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Kendra index is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Kendra index is encrypted with ${currentEncryptionLevelString} \
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
