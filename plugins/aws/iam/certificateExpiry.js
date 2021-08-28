var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Certificate Expiry',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Detect upcoming expiration of certificates used with ELBs',
    more_info: 'Certificates that have expired will trigger warnings in all major browsers',
    link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-update-ssl-cert.html',
    recommended_action: 'Update your certificates before the expiration date',
    apis: ['IAM:listServerCertificates'],
    settings: {
        certificate_expiry_pass: {
            name: 'Certificate Expiry Pass',
            description: 'Return a passing result when certificate expiration date exceeds this number of days in the future',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 45
        },
        certificate_expiry_warn: {
            name: 'Certificate Expiry Warn',
            description: 'Return a warning result when certificate expiration date exceeds this number of days in the future',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 30
        }
    },
    asl: {
        conditions: [
            {
                service: 'iam',
                api: 'listServerCertificates',
                property: 'Expiration',
                transform: 'DAYSFROM',
                op: 'GT',
                value: 90
            }
        ]
    },

    run: function(cache, settings, callback) {
        var config = {
            certificate_expiry_pass: settings.certificate_expiry_pass || this.settings.certificate_expiry_pass.default,
            certificate_expiry_warn: settings.certificate_expiry_warn || this.settings.certificate_expiry_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listServerCertificates = helpers.addSource(cache, source,
            ['iam', 'listServerCertificates', region]);

        if (!listServerCertificates) return callback(null, results, source);

        if (listServerCertificates.err || !listServerCertificates.data) {
            helpers.addResult(results, 3,
                'Unable to query for certificates: ' + helpers.addError(listServerCertificates));
            return callback(null, results, source);
        }

        if (!listServerCertificates.data.length) {
            helpers.addResult(results, 0, 'No certificates found');
            return callback(null, results, source);
        }

        var now = new Date();

        for (var i in listServerCertificates.data) {
            if (listServerCertificates.data[i].ServerCertificateName && listServerCertificates.data[i].Expiration) {
                var certificate = listServerCertificates.data[i];

                var then = new Date(certificate.Expiration);
                
                var difference = helpers.daysBetween(then, now);
                var expiresInMsg = 'Certificate: ' + certificate.ServerCertificateName + ' expires in ' + Math.abs(difference) + ' days';
                var expiredMsg = 'Certificate: ' + certificate.ServerCertificateName + ' expired ' + Math.abs(difference) + ' days ago';

                // Expired already
                if (then < now) {
                    helpers.addResult(results, 2, expiredMsg, 'global', certificate.Arn);
                } else {
                    // Expires in the future
                    if (difference > config.certificate_expiry_pass) {
                        helpers.addResult(results, 0, expiresInMsg, 'global', certificate.Arn, custom);
                    } else if (difference > config.certificate_expiry_warn) {
                        helpers.addResult(results, 1, expiresInMsg, 'global', certificate.Arn, custom);
                    } else if (difference > 0) {
                        helpers.addResult(results, 2, expiresInMsg, 'global', certificate.Arn, custom);
                    } else {
                        helpers.addResult(results, 0, expiredMsg, 'global', certificate.Arn, custom);
                    }
                }
            }
        }

        callback(null, results, source);
    }
};