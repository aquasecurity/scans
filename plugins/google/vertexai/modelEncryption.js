var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Vertex AI Model Encryption',
    category: 'AI & ML',
    owasp: ['LLM010', 'LLM07'],
    domain: 'Machine Learning',
    severity: 'High',
    description: 'Ensure that Vertex AI models are encrypted using desired encryption protection level.',
    more_info: 'By default Google encrypts all models using Google-managed encryption keys. To have more control over the encryption process of your Vertex AI models you can use Customer-Managed Keys (CMKs).',
    link: 'https://cloud.google.com/vertex-ai/docs/general/cmek',
    recommended_action: 'Recreate existing models with desired protection level.',
    apis: ['vertexAI:listModels', 'keyRings:list', 'cryptoKeys:list'],
    realtime_triggers: ['aiplatform.ModelService.UpdateModel', 'aiplatform.ModelService.DeleteModel'],
    settings: {
        vertexai_model_encryption_protection_level: {
            name: 'Vertex AI Model Encryption Protection Level',
            description: 'Desired protection level for Vertex AI models. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.vertexai_model_encryption_protection_level || this.settings.vertexai_model_encryption_protection_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        var keysObj = {};

        async.series([
            function(cb) {
                async.each(regions.cryptoKeys, function(region, rcb) {
                    let cryptoKeys = helpers.addSource(
                        cache, source, ['cryptoKeys', 'list', region]);

                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {
                async.each(regions.vertexAI, function(region, rcb) {
                    let models = helpers.addSource(cache, source,
                        ['vertexAI', 'listModels', region]);

                    if (!models) return rcb();

                    if (models.err || !models.data) {
                        helpers.addResult(results, 3, 'Unable to query Vertex AI models: ' + helpers.addError(models), region);
                        return rcb();
                    }

                    if (!models.data.length) {
                        helpers.addResult(results, 0, 'No existing Vertex AI models found', region);
                        return rcb();
                    }

                    async.each(models.data, (model) => {
                        let currentEncryptionLevel;

                        if (model.encryptionSpec && model.encryptionSpec.kmsKeyName) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[model.encryptionSpec.kmsKeyName], helpers.PROTECTION_LEVELS);
                        } else {
                            currentEncryptionLevel = 1; //default
                        }

                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `Vertex AI model has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                region, model.name);
                        } else {
                            helpers.addResult(results, 2,
                                `Vertex AI model has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
                                region, model.name);
                        }

                    });
                    rcb();
                }, function() {
                    cb();
                });
            }
        ], function() {
            callback(null, results, source);
        });
    }
};
