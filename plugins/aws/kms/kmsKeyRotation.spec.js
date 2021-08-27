var expect = require('chai').expect;
const kmsKeyRotation = require('./kmsKeyRotation');

const listKeys = {
    KeyId: "60c4f21b-e271-4e97-86ae-6403618a9467",
    KeyArn: "arn:aws:kms:us-east-1:111122223333:key/60c4f21b-e271-4e97-86ae-6403618a9467"
};

const describeKey = [
    {
        KeyMetadata: {
            AWSAccountId: "111122223333", 
            Arn: "arn:aws:kms:us-east-1:111122223333:key/60c4f21b-e271-4e97-86ae-6403618a9467", 
            CreationDate: "2020-08-26T16:55:28+00:00", 
            CustomerMasterKeySpec: "SYMMETRIC_DEFAULT", 
            Description: "", 
            Enabled: true, 
            EncryptionAlgorithms: [
                "SYMMETRIC_DEFAULT"
            ], 
            KeyId: "60c4f21b-e271-4e97-86ae-6403618a9467", 
            KeyManager: "CUSTOMER", 
            KeyState: "Enabled", 
            KeyUsage: "ENCRYPT_DECRYPT", 
            MultiRegion: false, 
            Origin: "AWS_KMS"
        }
    },
    {
        KeyMetadata: {
            AWSAccountId: "111122223333", 
            Arn: "arn:aws:kms:us-east-1:111122223333:key/60c4f21b-e271-4e97-86ae-6403618a9467", 
            CreationDate: "2020-08-26T16:55:28+00:00", 
            CustomerMasterKeySpec: "SYMMETRIC_DEFAULT", 
            Description: "", 
            Enabled: true, 
            EncryptionAlgorithms: [
                "SYMMETRIC_DEFAULT"
            ], 
            KeyId: "60c4f21b-e271-4e97-86ae-6403618a9467", 
            KeyManager: "CUSTOMER", 
            KeyState: "Enabled", 
            KeyUsage: "ENCRYPT_DECRYPT", 
            MultiRegion: false, 
            Origin: "AWS_KMS"
        }
    },
    {
        KeyMetadata: {
            AWSAccountId: "111122223333", 
            Arn: "arn:aws:kms:us-east-1:111122223333:key/60c4f21b-e271-4e97-86ae-6403618a9467", 
            CreationDate: "2020-08-26T16:55:28+00:00", 
            CustomerMasterKeySpec: "SYMMETRIC_DEFAULT", 
            Description: "", 
            Enabled: true, 
            EncryptionAlgorithms: [
                "SYMMETRIC_DEFAULT"
            ], 
            KeyId: "60c4f21b-e271-4e97-86ae-6403618a9467", 
            KeyManager: "AWS", 
            KeyState: "PendingDeletion", 
            KeyUsage: "ENCRYPT_DECRYPT", 
            MultiRegion: false, 
            Origin: "AWS_KMS"
        }
    }
]

const keyPolicy = [
    {
        "Version" : "2012-10-17",
        "Id" : "key-default-1",
        "Statement" : [ 
            {
                "Sid" : "Enable IAM User Permissions",
                "Effect" : "Allow",
                "Principal" : {
                    "AWS" : "arn:aws:iam::111122223333:root"
                },
                "Action" : "kms:*",
                "Resource" : "*"
            }
        ]
    },
    {
        "Version" : "2012-10-17",
        "Id" : "aqua-cspm",
        "Statement" : [ 
            {
                "Sid" : "Enable IAM User Permissions",
                "Effect" : "Allow",
                "Principal" : {
                    "AWS" : "arn:aws:iam::111122223333:root"
                },
                "Action" : "kms:*",
                "Resource" : "*"
            }
        ]
    }
    
]

const keyRotationStatus = [
    {
        KeyRotationEnabled: true
    },
    {
        KeyRotationEnabled: false
    }
]

const createCache = (keys, describeKey, keyPolicy, keyRotation) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    return {
        kms:{
            listKeys: {
                'us-east-1': {
                    data: keys
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        data: describeKey
                    }
                }
            },
            getKeyPolicy: {
                'us-east-1': {
                    [keyId]: {
                        data: keyPolicy
                    }
                }
            },
            getKeyRotationStatus: {
                'us-east-1': {
                    [keyId]: {
                        data: keyRotation
                    }
                },
            }
        },
    };
};

const createErrorCache = () => {
    return {
        kms: {
            listKeys: {
                'us-east-1': {
                    err: 'Unable to list keys ' 
                }
            },
            describeKey: {
                'us-east-1': {
                    ['id']: {
                        err: 'Unable to describe key'
                    }
                }
            },
            getKeyPolicy: {
                'us-east-1': {
                    ['id']: {
                        err: 'Unable to get key policy' 
                    }
                }
            },
            getKeyRotationStatus: {
                'us-east-1': {
                    ['id']: {
                        err: 'Unable to get key rotation status' 
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        kms: {
            listKeys: {
                'us-east-1': null
            },
            describeKey: {
                'us-east-1': null
            },
            getKeyPolicy: {
                'us-east-1': null
            },
            getKeyRotationStatus: {
                'us-east-1': null
            }
        }  
    };
};

describe('kmsKeyRotation', function () {
    describe('run', function () {
        it('should PASS if KMS has encryption greater than awskms and has rotation enabled', function (done) {
            const cache = createCache([listKeys], describeKey[1], keyPolicy[0], keyRotationStatus[0]);
            kmsKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if KMS has encryption greater than awskms and has rotation disabled', function (done) {
            const cache = createCache([listKeys], describeKey[1], keyPolicy[0], keyRotationStatus[1]);
            kmsKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        
        it('should PASS if no KMS keys found', function (done) {
            const cache = createCache([], {}, {}, {});
            kmsKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createErrorCache();
            kmsKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return if KMS encryption level is lower than or equal to awskms', function (done) {
            const cache = createCache([listKeys], describeKey[2], keyPolicy[0], keyRotationStatus[1]);
            kmsKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        
        it('should not return any result if list keys response is not found', function (done) {
            const cache = createNullCache();
            kmsKeyRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});