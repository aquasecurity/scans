var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Audio Logs Encrypted',
    category: 'AI & ML',
    owasp: ['LLM02'],
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensure that Amazon Lex audio logs are encrypted using desired KMS encryption level',
    more_info: 'For audio logs you use default encryption on your S3 bucket or specify an AWS KMS key to encrypt your audio objects. Even if your S3 bucket uses default encryption you can still specify a different AWS KMS key to encrypt your audio objects for enhanced security.',
    link: 'https://docs.aws.amazon.com/lex/latest/dg/conversation-logs-encrypting.html',
    recommended_action: 'Encrypt Lex audio logs with customer-manager keys (CMKs) present in your account',
    apis: ['LexModelsV2:listBots', 'LexModelsV2:listBotAliases', 'LexModelsV2:describeBotAlias',
        'KMS:describeKey', 'KMS:listKeys', 'STS:getCallerIdentity'],
    settings: {
        audio_logs_desired_encryption_level: {
            name: 'Lex Audio Logs Target Encryption Level',
            description: 'In order (lowest to highest) sse=S3-SSE; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk'
        }
    },
    realtime_triggers: ['lexmodelsV2:CreateBotAlias', 'lexmodelsV2:UpdateBotAlias', 'lexmodelsV2:DeleteBotAlias'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.regions(settings);
        
        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        var config = {
            desiredEncryptionLevelString: settings.audio_logs_desired_encryption_level || this.settings.audio_logs_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(region.lexmodelsv2, function(region, rcb){
            var listBots = helpers.addSource(cache, source,
                ['lexmodelsv2', 'listBots', region]);
            
            if (!listBots) return rcb();

            if (listBots.err || !listBots.data) {
                helpers.addResult(results, 3,
                    'Unable to query for  Lex bots: ' + helpers.addError(listBots),region);
                return rcb();
            }

            if (!listBots.data.length) {
                helpers.addResult(results, 0, 'No  Lex bots found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            for (let bot of listBots.data){
                if (!bot.botId) continue;

                var resource = `arn:${awsOrGov}:lex:${region}:${accountId}:bot/${bot.botId}`;

                var listBotAliases = helpers.addSource(cache, source,
                    ['lexmodelsv2', 'listBotAliases', region, bot.botId]);

                if (!listBotAliases || listBotAliases.err || !listBotAliases.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Lex bot aliases: ' + bot.botId + ': ' + helpers.addError(listBotAliases),
                        region, resource);
                    continue;
                }

                if (!listBotAliases.data.botAliasSummaries || !listBotAliases.data.botAliasSummaries.length) {
                    helpers.addResult(results, 0,
                        'No bot aliases found', region, resource);
                    continue;
                }

                for (let alias of listBotAliases.data.botAliasSummaries) {
                    if (!alias.botAliasId) continue;

                    var aliasArn = `arn:${awsOrGov}:lex:${region}:${accountId}:bot-alias/${bot.botId}/${alias.botAliasId}`;

                    var describeBotAlias = helpers.addSource(cache, source,
                        ['lexmodelsv2', 'describeBotAlias', region, alias.botAliasId]);

                    if (!describeBotAlias ||
                        describeBotAlias.err ||
                        !describeBotAlias.data) {
                        helpers.addResult(results, 3,
                            'Unable to query Lex bot alias: ' + helpers.addError(describeBotAlias), region, aliasArn);
                        continue;
                    }

                    if (!describeBotAlias.data.conversationLogSettings ||
                        !describeBotAlias.data.conversationLogSettings.audioLogSettings) {
                        helpers.addResult(results, 0,
                            'Bot alias does not have any audio logs configured', region, aliasArn);
                        continue;
                    }

                    let found = false;

                    for (let audioLog of describeBotAlias.data.conversationLogSettings.audioLogSettings){
                        if (audioLog.destination && 
                            audioLog.destination.s3Bucket) {
                            found = true;
                        }
        
                        if (audioLog.destination.s3Bucket.kmsKeyArn) {
                            var KmsKey =  audioLog.destination.s3Bucket.kmsKeyArn;
                            var keyId = KmsKey.split('/')[1] ? KmsKey.split('/')[1] : KmsKey;
        
                            var describeKey = helpers.addSource(cache, source,
                                ['kms', 'describeKey', region, keyId]);  
        
                            if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                                helpers.addResult(results, 3,
                                    `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                    region, KmsKey);
                                continue;
                            }
        
                            currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                        
                        } else currentEncryptionLevel = 1; //sse
        
                    }

                    if (!found) {
                        helpers.addResult(results, 2,
                            'Bot alias is not saving audio logs on S3', region, aliasArn);
                        continue;
                    }
        
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
        
                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Bot audio logs are encrypted with ${currentEncryptionLevelString} \
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, aliasArn);
                    } else {
                        helpers.addResult(results, 2,
                            `Bot audio logs are encrypted with ${currentEncryptionLevelString} \
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, aliasArn);
                    }
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};