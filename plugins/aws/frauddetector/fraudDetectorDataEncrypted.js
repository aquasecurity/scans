var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Fraud Detector Data Encrypted',
    category: 'AI & ML',
    owasp: ['LLM04', 'LLM02'],
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensure that Amazon Fraud Detector has encryption enabled for data at rest with desired KMS encryption level.',
    more_info: 'Amazon Fraud Detector encrypts your data at rest with AWS-managed KMS key. Use customer-manager KMS keys (CMKs) instead in order to follow your organizations\'s security and compliance requirements.',
    recommended_action: 'Enable encryption for data at rest using PutKMSEncryptionKey API',
    link: 'https://docs.aws.amazon.com/frauddetector/latest/ug/encryption-at-rest.html',
    apis: ['FraudDetector:getDetectors', 'FraudDetector:getKMSEncryptionKey', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        fraud_detector_data_encryption_level: {
            name: 'Fraud Detector Data Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms'
        }
    },
    realtime_triggers: ['frauddetector:PutKMSEncryptionKey', 'frauddetector:DeleteDetector'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.fraud_detector_data_encryption_level || this.settings.fraud_detector_data_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.connect, function(region, rcb){
            var listDetectors = helpers.addSource(cache, source,
                ['frauddetector', 'getDetectors', region]);

            if (!listDetectors) return rcb();

            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3,
                    `Unable to query Fraud Detectors: ${helpers.addError(listDetectors)}`, region);
                return rcb();
            }

            if (!listDetectors.data.length) {
                helpers.addResult(results, 0, 'No Fraud Detectors found', region);
                return rcb();
            }

            var fraudDetectorsEncryptionKey = helpers.addSource(cache, source,
                ['frauddetector', 'getKMSEncryptionKey', region]);

            if (fraudDetectorsEncryptionKey.err || !fraudDetectorsEncryptionKey.data) {
                helpers.addResult(results, 3,
                    `Unable to query Fraud Detectors Key: ${helpers.addError(listDetectors)}`, region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            if (fraudDetectorsEncryptionKey.data && fraudDetectorsEncryptionKey.data.kmsEncryptionKeyArn
                    && fraudDetectorsEncryptionKey.data.kmsEncryptionKeyArn.toUpperCase() !== 'DEFAULT') {
                let encryptionKey = fraudDetectorsEncryptionKey.data.kmsEncryptionKeyArn;
                var keyId = encryptionKey.split('/')[1] ? encryptionKey.split('/')[1] : encryptionKey;

                var describeKey = helpers.addSource(cache, source,
                    ['kms', 'describeKey', region, keyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                        region, encryptionKey);
                    return rcb();    
                }

                currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);

            } else {
                currentEncryptionLevel = 2; //awskms
            }

            var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                helpers.addResult(results, 0,
                    `Fraud Detectors Data is encrypted with ${currentEncryptionLevelString} \
                    which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                    region);
            } else {
                helpers.addResult(results, 2,
                    `Fraud Detectors Data is encrypted with ${currentEncryptionLevelString} \
                    which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                    region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
