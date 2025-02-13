var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Translate Job Output Encrypted',
    category: 'AI & ML',
    owasp: ['LLM02'],
    domain: 'Compute',
    severity: 'High',
    description: 'Ensure that your Amazon Translate jobs have CMK encryption enabled for output data residing on S3.',
    more_info: 'Amazon Translate encrypts your output data with AWS-manager keys by default. ' +
        'Encrypt your files using customer-managed keys in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Create Translate jobs with customer-manager keys (CMKs).',
    link: 'https://docs.aws.amazon.com/translate/latest/dg/encryption-at-rest.html',
    apis: ['Translate:listTextTranslationJobs', 'KMS:listKeys', 'KMS:describeKey', 'STS:getCallerIdentity'],
    settings: {
        translate_job_encryption_level: {
            name: 'Translate Job Target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        }
    },
    realtime_triggers: ['translate:StartTextTranslationJob', 'translate:StopTextTranslationJob'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.translate_job_encryption_level || this.settings.translate_job_encryption_level.default
        };

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.translate, function(region, rcb){
            var listTextTranslationJobs = helpers.addSource(cache, source,
                ['translate', 'listTextTranslationJobs', region]);

            if (!listTextTranslationJobs) return rcb();

            if (listTextTranslationJobs.err || !listTextTranslationJobs.data) {
                helpers.addResult(results, 3,
                    `Unable to list Translate text jobs: ${helpers.addError(listTextTranslationJobs)}`, region);
                return rcb();
            }

            if (!listTextTranslationJobs.data.length) {
                helpers.addResult(results, 0,
                    'No Translate text jobs found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let job of listTextTranslationJobs.data) {
                if (!job.JobName) continue;

                var resource = `arn:${awsOrGov}:translate:${region}:${accountId}:job/${job.JobName}`;

                if (job.OutputDataConfig) {
                    if (job.OutputDataConfig && job.OutputDataConfig.EncryptionKey && job.OutputDataConfig.EncryptionKey.Id) {
                        var kmsKeyId = job.OutputDataConfig.EncryptionKey.Id.split('/')[1] ? job.OutputDataConfig.EncryptionKey.Id.split('/')[1] : job.OutputDataConfig.EncryptionKey.Id;
    
                        var describeKey = helpers.addSource(cache, source,
                            ['kms', 'describeKey', region, kmsKeyId]);
    
                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                            helpers.addResult(results, 3,
                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                region, job.OutputDataConfig.EncryptionKey.Id);
                            continue;
                        }
    
                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    } else {
                        currentEncryptionLevel = 2; //awskms
                    }
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
    
                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Translate job is encrypted with ${currentEncryptionLevelString} \
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Translate job is encrypted with ${currentEncryptionLevelString} \
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 3,
                        'Unable to find output data config for the job',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};