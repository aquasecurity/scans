var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'HealthLake Data Store Encrypted',
    category: 'AI & ML',
    owasp: ['LLM04', 'LLM02'],
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensure that AWS HealthLake Data Store is using desired encryption level.',
    more_info: 'Amazon HealthLake is a Fast Healthcare Interoperability Resources (FHIR)-enabled patient Data Store that uses AWS-managed KMS keys for encryption. ' +
               'Encrypt these data stores using customer-managed keys (CMKs) in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create HealthLake Data Store with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/healthlake/latest/devguide/data-protection.html',
    apis: ['HealthLake:listFHIRDatastores', 'KMS:describeKey', 'KMS:listKeys'],
    settings: {
        healthlake_datastore_desired_encryption_level: {
            name: 'HealthLake Data Store Desired Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms'
        }
    },
    realtime_triggers: ['healthlake:CreateFHIRDatastore', 'healthlake:DeleteFHIRDatastore'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.healthlake_datastore_desired_encryption_level || this.settings.healthlake_datastore_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.healthlake, function(region, rcb){
            var listFHIRDatastores = helpers.addSource(cache, source,
                ['healthlake', 'listFHIRDatastores', region]);

            if (!listFHIRDatastores) return rcb();

            if (listFHIRDatastores.err || !listFHIRDatastores.data) {
                helpers.addResult(results, 3, `Unable to query HealthLake Data Store: ${helpers.addError(listFHIRDatastores)}`, region);
                return rcb();
            }

            if (!listFHIRDatastores.data.length) {
                helpers.addResult(results, 0, 'No HealthLake data stores found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let datastore of listFHIRDatastores.data) {
                if (!datastore.DatastoreArn) continue;

                let resource = datastore.DatastoreArn;

                if (datastore.SseConfiguration &&
                    datastore.SseConfiguration.KmsEncryptionConfig &&
                    datastore.SseConfiguration.KmsEncryptionConfig.KmsKeyId) {

                    var kmskey = datastore.SseConfiguration.KmsEncryptionConfig.KmsKeyId;
                    var kmsKeyId = kmskey.split('/')[1] ? kmskey.split('/')[1] : kmskey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmskey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `HealthLake data store is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `HealthLake data store is encrypted with ${currentEncryptionLevelString} \
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