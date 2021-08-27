var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'KMS Key Rotation',
    category: 'KMS',
    description: 'Ensures KMS keys are set to rotate on a regular schedule',
    more_info: 'All KMS keys should have key rotation enabled. AWS will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.',
    recommended_action: 'Enable yearly rotation for the KMS key',
    link: 'http://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html',
    apis: ['KMS:listKeys', 'KMS:describeKey', 'KMS:getKeyRotationStatus', 'KMS:getKeyPolicy'],
    compliance: {
        pci: 'PCI has strict requirements regarding the use of encryption keys ' +
             'to protect cardholder data. These requirements include rotating ' +
             'the key periodically. KMS provides key rotation capabilities that ' +
             'should be enabled.',
        cis2: '2.8 Ensure rotation for customer created CMKs is enabled'
    },
    settings: {
        kms_key_policy_whitelisted_policy_ids: {
            name: 'KMS Key Policy Whitelisted Policy IDs',
            description: 'A comma-delimited list of known Key Policy IDs that should be trusted',
            regex: '^.{1,255}$',
            default: 'aqua-cspm'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            kms_key_policy_whitelisted_policy_ids: settings.kms_key_policy_whitelisted_policy_ids || this.settings.kms_key_policy_whitelisted_policy_ids.default
        };

        if (config.kms_key_policy_whitelisted_policy_ids &&
            config.kms_key_policy_whitelisted_policy_ids.length) {
            config.kms_key_policy_whitelisted_policy_ids = config.kms_key_policy_whitelisted_policy_ids.split(',');
        } else {
            config.kms_key_policy_whitelisted_policy_ids = [];
        }

        async.each(regions.kms, function(region, rcb){
            
            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            if (!listKeys.data.length) {
                helpers.addResult(results, 0, 'No KMS keys found', region);
                return rcb();                
            }

            listKeys.data.forEach(kmsKey => {
                if (!kmsKey.KeyId) return;

                var getKeyPolicy = helpers.addSource(cache, source,
                    ['kms', 'getKeyPolicy', region, kmsKey.KeyId]);

                if (!getKeyPolicy || getKeyPolicy.err || !getKeyPolicy.data){
                    helpers.addResult(results, 3,
                        'Unable to get key policy: ' + helpers.addError(getKeyPolicy),
                        region, kmsKey.KeyArn);
                    return;
                }

                // Auq-CSPM keys for Remediations should be skipped. 
                // The only way to distinguish these keys is the Policy Id.
                if (getKeyPolicy.data.Id &&
                    config.kms_key_policy_whitelisted_policy_ids.length &&
                    config.kms_key_policy_whitelisted_policy_ids.indexOf(getKeyPolicy.data.Id)>-1) {
                    helpers.addResult(results, 0, 'The key ' + kmsKey.KeyArn + ' is whitelisted.', region, kmsKey.KeyArn);
                    return;
                }

                var describeKey = helpers.addSource(cache, source,
                    ['kms', 'describeKey', region, kmsKey.KeyId]);
                
                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        'Unable to describe key: ' + helpers.addError(describeKey),
                        region, kmsKey.KeyArn);
                    return;
                }

                var describeKeyData = describeKey.data;

                // AWS-generated keys for CodeCommit, ACM, etc. should be skipped.
                // Also skip keys that are being deleted 
                const currentEncryptionLevel = helpers.getEncryptionLevel(describeKeyData.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                if (currentEncryptionLevel <= 2 ||
                    (describeKeyData.KeyMetadata.KeyState &&
                    describeKeyData.KeyMetadata.KeyState.toUpperCase() === 'PENDINGDELETION'))  return;

                // Skip keys that are imported into KMS
                if (describeKeyData.KeyMetadata &&
                    describeKeyData.KeyMetadata.Origin &&
                    describeKeyData.KeyMetadata.Origin !== 'AWS_KMS') {
                    return;
                }

                var getKeyRotationStatus = helpers.addSource(cache, source,
                    ['kms', 'getKeyRotationStatus', region, kmsKey.KeyId]);
                
                if (!getKeyRotationStatus || getKeyRotationStatus.err || !getKeyRotationStatus.data){
                    helpers.addResult(results, 3,
                        'Unable to get key rotation status: ' + helpers.addError(getKeyRotationStatus),
                        region, kmsKey.KeyArn);
                    return;
                }

                var enabled = getKeyRotationStatus.data.KeyRotationEnabled;
                var status = enabled ? 0 : 2;

                helpers.addResult(results, status, `Key rotation is ${enabled ? '' : 'not'} enabled`, region, kmsKey.KeyArn);
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};