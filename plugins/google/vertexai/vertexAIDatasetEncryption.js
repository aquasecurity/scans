var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Vertex AI Dataset Encryption',
    category: 'AI & ML',
    owasp: ['LLM02', 'LLM04', 'LLM10'],
    domain: 'Machine Learning',
    severity: 'High',
    description: 'Ensure that Vertex AI datasets are encrypted using desired encryption protection level.',
    more_info: 'By default Google encrypts all datasets using Google-managed encryption keys. To have more control over the encryption process of your Vertex AI datasets you can use Customer-Managed Keys (CMKs).',
    link: 'https://cloud.google.com/vertex-ai/docs/general/cmek',
    recommended_action: 'Recreate existing datasets with desired protection level.',
    apis: ['vertexAI:listDatasets', 'keyRings:list', 'cryptoKeys:list'],
    realtime_triggers: ['aiplatform.DatasetService.CreateDataset', 'aiplatform.DatasetService.UpdateDataset', 'aiplatform.DatasetService.DeleteDataset'],
    settings: {
        vertexai_dataset_encryption_protection_level: {
            name: 'Vertex AI Dataset Encryption Protection Level',
            description: 'Desired protection level for Vertex AI datasets. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.vertexai_dataset_encryption_protection_level || this.settings.vertexai_dataset_encryption_protection_level.default;
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
                    let datasets = helpers.addSource(cache, source,
                        ['vertexAI', 'listDatasets', region]);

                    if (!datasets) return rcb();

                    if (datasets.err || !datasets.data) {
                        helpers.addResult(results, 3, 'Unable to query Vertex AI datasets: ' + helpers.addError(datasets), region);
                        return rcb();
                    }

                    if (!datasets.data.length) {
                        helpers.addResult(results, 0, 'No existing Vertex AI datasets found', region);
                        return rcb();
                    }

                    async.each(datasets.data, (dataset) => {
                        let currentEncryptionLevel;

                        if (dataset.encryptionSpec && dataset.encryptionSpec.kmsKeyName) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[dataset.encryptionSpec.kmsKeyName], helpers.PROTECTION_LEVELS);
                        } else {
                            currentEncryptionLevel = 1; //default
                        }

                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `Vertex AI dataset has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                region, dataset.name);
                        } else {
                            helpers.addResult(results, 2,
                                `Vertex AI dataset has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
                                region, dataset.name);
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

