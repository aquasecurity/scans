var helpers = require('../../../helpers/aws/');

module.exports = {
    title: 'S3 Bucket All Users Policy',
    category: 'S3',
    description: 'Ensures S3 bucket policies do not allow global write, delete, or read permissions',
    more_info: 'S3 buckets can be configured to allow the global principal to access the bucket via the bucket policy. This policy should be restricted only to known users or accounts.',
    recommended_action: 'Remove wildcard principals from the bucket policy statements.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'S3:getBucketLocation'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. If PCI-restricted data is stored in S3, ' +
             'those buckets should not enable global user access.'
    },
    remediation_description: 'Bucket policy will be deleted for affected buckets.',
    remediation_min_version: '202108172230',
    apis_remediate: ['S3:listBuckets', 'S3:getBucketLocation'],
    actions: {
        remediate: ['S3:deleteBucketPolicy'],
        rollback: ['S3:putBucketPolicy']
    },
    permissions: {
        remediate: ['s3:DeleteBucketPolicy'],
        rollback: ['s3:PutBucketPolicy']
    },
    realtime_triggers: [],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        for (var i in listBuckets.data) {
            var bucket = listBuckets.data[i];
            if (!bucket.Name) continue;

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucket.Name]);

            // Check the bucket policy
            if (getBucketPolicy && getBucketPolicy.err &&
                getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 0,
                    'No additional bucket policy found',
                    'global', bucketResource);
            } else if (!getBucketPolicy || getBucketPolicy.err ||
                       !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3,
                    'Error querying for bucket policy for bucket: ' + bucket.Name +
                    ': ' + helpers.addError(getBucketPolicy),
                    'global', bucketResource);
            } else {
                try {
                    var policyJson = JSON.parse(getBucketPolicy.data.Policy);
                    getBucketPolicy.data.Policy = policyJson;

                    if (!policyJson || !policyJson.Statement) {
                        helpers.addResult(results, 3,
                            'Error querying for bucket policy for bucket: ' + bucket.Name +
                            ': Policy JSON is invalid or does not contain valid statements.',
                            'global', bucketResource);
                    } else if (!policyJson.Statement.length) {
                        helpers.addResult(results, 0,
                            'Bucket policy does not contain any statements',
                            'global', bucketResource);
                    } else {
                        var policyMessage = [];
                        var policyResult = 0;

                        for (var s in policyJson.Statement) {
                            var statement = policyJson.Statement[s];

                            if (statement.Effect && statement.Effect === 'Allow') {
                                if (statement.Principal) {
                                    var starPrincipal = false;

                                    if (typeof statement.Principal === 'string') {
                                        if (statement.Principal === '*') {
                                            starPrincipal = true;
                                        }
                                    } else if (typeof statement.Principal === 'object') {
                                        if (statement.Principal.Service &&
                                            statement.Principal.Service === '*') {
                                            starPrincipal = true;
                                        } else if (statement.Principal.AWS &&
                                            statement.Principal.AWS === '*') {
                                            starPrincipal = true;
                                        } else if (statement.Principal.length &&
                                            statement.Principal.indexOf('*') > -1) {
                                            starPrincipal = true;
                                        }
                                    }

                                    if (starPrincipal) {
                                        if (statement.Condition) {
                                            if (policyResult < 1) policyResult = 1;
                                            policyMessage.push('Principal * allowed to conditionally perform: ' + statement.Action);
                                        } else {
                                            if (policyResult < 2) policyResult = 2;
                                            policyMessage.push('Principal * allowed to perform: ' + statement.Action);
                                        }   
                                    }
                                }
                            }
                        }

                        if (!policyMessage.length) {
                            helpers.addResult(results, 0,
                                'Bucket policy does not contain any insecure allow statements',
                                'global', bucketResource);
                        } else {
                            helpers.addResult(results, policyResult,
                                policyMessage.join(' '),
                                'global', bucketResource);
                        }
                    }
                } catch (e) {
                    helpers.addResult(results, 3,
                        'Error querying for bucket policy for bucket: ' + bucket.Name +
                        ': Policy JSON could not be parsed.',
                        'global', bucketResource);
                }
            }
        }
        
        callback(null, results, source);
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'bucketAllUsersPolicy';
        var bucketNameArr = resource.split(':');
        var bucketName = bucketNameArr[bucketNameArr.length - 1];

        // find the location of the bucket needing to be remediated
        var bucketLocations = cache['s3']['getBucketLocation'];
        var bucketLocation;

        for (var key in bucketLocations) {
            if (bucketLocations[key][bucketName]) {
                bucketLocation = key;
                break;
            }
        }

        // add the location of the bucket to the config
        config.region = bucketLocation;

        // create the params necessary for the remediation
        var params = {
            Bucket: bucketName
        };

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Policy': 'Enabled',
            'Bucket': bucketName
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
                'Policy': 'Disabled',
                'Bucket': bucketName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};