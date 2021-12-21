var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, retries, callback) {
    var lexmodelsv2 = new AWS.LexModelsV2(AWSConfig);

    if (!collection.lexmodelsv2 ||
        !collection.lexmodelsv2.listBots ||
        !collection.lexmodelsv2.listBots[AWSConfig.region] ||
        !collection.lexmodelsv2.listBots[AWSConfig.region].data) return callback();
    async.eachLimit(collection.lexmodelsv2.listBots[AWSConfig.region].data, 5, function(bot, cb){
     
        if (!bot.botId || !collection.lexmodelsv2 ||
            !collection.lexmodelsv2.listBotAliases ||
            !collection.lexmodelsv2.listBotAliases[AWSConfig.region] ||
            !collection.lexmodelsv2.listBotAliases[AWSConfig.region][bot.botId] ||
            !collection.lexmodelsv2.listBotAliases[AWSConfig.region][bot.botId].data ||
            !collection.lexmodelsv2.listBotAliases[AWSConfig.region][bot.botId].data.botAliasSummaries ||
            !collection.lexmodelsv2.listBotAliases[AWSConfig.region][bot.botId].data.botAliasSummaries.length) {
            return cb();
        }

        async.eachLimit(collection.lexmodelsv2.listBotAliases[AWSConfig.region][bot.botId].data.botAliasSummaries, 3, function(alias, pCb){
            collection.lexmodelsv2.describeBotAlias[AWSConfig.region][alias.botAliasId] = {};

            lexmodelsv2.describeBotAlias({
                botAliasId: alias.botAliasId,
                botId: bot.botId
            }, function(err, data){
                if (err) {
                    collection.lexmodelsv2.describeBotAlias[AWSConfig.region][alias.botAliasId].err = err;
                }

                collection.lexmodelsv2.describeBotAlias[AWSConfig.region][alias.botAliasId].data = data;
                pCb();
            });
        }, function(){
            setTimeout(function(){
                cb();
            }, 100);
        });
    }, function(){
        callback();
    });
};