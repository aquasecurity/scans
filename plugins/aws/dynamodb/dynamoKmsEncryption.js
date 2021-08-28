var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB KMS Encryption',
    category: 'DynamoDB',
    domain: 'Databases',
    description: 'Ensures DynamoDB tables are encrypted using a customer-owned KMS key.',
    more_info: 'DynamoDB tables can be encrypted using AWS-owned or customer-owned KMS keys. Customer keys should be used to ensure control over the encryption seed data.',
    link: 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html',
    recommended_action: 'Create a new DynamoDB table using a CMK KMS key.',
    apis: ['DynamoDB:listTables', 'DynamoDB:describeTable', 'STS:getCallerIdentity', 'KMS:listKeys', 'KMS:describeKey'],
    remediation_description: 'The impacted DynamoDB table will be configured to use either KMS encryption with AWS managed CMK, or CMK-based encryption if a KMS key ID is provided.',
    remediation_min_version: '202001121300',
    apis_remediate: ['DynamoDB:listTables', 'KMS:listKeys', 'KMS:describeKey'],
    actions: {
        remediate: ['DynamoDB:updateTable'],
        rollback: ['DynamoDB:updateTable']
    },
    permissions: {
        remediate: ['DynamoDB:UpdateTable'],
        rollback: ['DynamoDB:UpdateTable']
    },
    remediation_inputs: {
        kmsKeyIdforDynamo: {
            name: '(Optional) DynamoDB KMS Key ID',
            description: 'The KMS Key ID used for encryption',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: false
        }
    },
    realtime_triggers: ['DynamoDB:UpdateTable', 'DynamoDB:CreateTable'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.dynamodb, function(region, rcb){
            var listTables = helpers.addSource(cache, source,
                ['dynamodb', 'listTables', region]);

            if (!listTables) return rcb();

            if (listTables.err || !listTables.data) {
                helpers.addResult(results, 3,
                    'Unable to query for DynamoDB tables: ' + helpers.addError(listTables), region);
                return rcb();
            }

            if (!listTables.data.length) {
                helpers.addResult(results, 0, 'No DynamoDB tables found', region);
                return rcb();
            }

            for (var i in listTables.data) {
                var table = listTables.data[i];

                var describeTable = helpers.addSource(cache, source,
                    ['dynamodb', 'describeTable', region, table]);

                var resource = `arn:${awsOrGov}:dynamodb:${region}:${accountId}:table/${table}`;

                if (describeTable.err || !describeTable.data || !describeTable.data.Table) {
                    helpers.addResult(results, 3,
                        'Unable to describe DynamoDB table: ' + helpers.addError(describeTable), region, resource);
                    return rcb();
                }


                if (describeTable.data.Table.SSEDescription &&
                    describeTable.data.Table.SSEDescription.Status &&
                    describeTable.data.Table.SSEDescription.Status.toUpperCase() === 'ENABLED') {
                    helpers.addResult(results, 0,
                        'Table encryption is enabled with a KMS master key', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Table is using default encryption with AWS-owned key', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'dynamoKmsEncryption';
        var tableNameArr = resource.split(':');
        var tableName = tableNameArr[tableNameArr.length - 1].split('/')[1];
        let defaultKeyDesc = 'Default master key that protects my DynamoDB data when no other key is defined';

        // find the location of the table needing to be remediated
        var tableLocation = tableNameArr[3];

        // add the location of the table to the config
        config.region = tableLocation;
        var params = {};

        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdforDynamo) {
            params = {
                'TableName': tableName,
                'SSESpecification': {
                    'Enabled': true,
                    'KMSMasterKeyId': settings.input.kmsKeyIdforDynamo,
                    'SSEType': 'KMS'
                }
            };
        } else {
            let defaultKmsKeyId = helpers.getDefaultKeyId(cache, config.region, defaultKeyDesc);
            if (!defaultKmsKeyId) return callback(`No default DynamoDB key for the region ${config.region}`);
            params = {
                'TableName': tableName,
                'SSESpecification': {
                    'Enabled': true,
                    'KMSMasterKeyId': defaultKmsKeyId,
                    'SSEType': 'KMS'
                }
            };
        }

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'DEFAULT',
            'DynamoDB': resource
        };
        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'ENCRYPTED',
                'DynamoDB': tableName
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};