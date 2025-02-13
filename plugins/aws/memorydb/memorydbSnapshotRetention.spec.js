var expect = require('chai').expect;
var memorydbSnapshotRetention = require('./memorydbSnapshotRetention');

const describeClusters = [
    {
        "Name": "aquacluster",
        "Status": "creating",
        "NumberOfShards": 1,
        "SubnetGroupName": "subnet1",
        "TLSEnabled": true,
        "ARN": "arn:aws:memorydb:us-east-1:000111222333:cluster/aquacluster",
        "SnapshotRetentionLimit": 1,
        "MaintenanceWindow": "wed:08:00-wed:09:00",
        "SnapshotWindow": "06:30-07:30",
        "ACLName": "open-access",
        "AutoMinorVersionUpgrade": true
    },
    {
        "Name": "aquacluster",
        "Status": "available",
        "NumberOfShards": 1,
        "ARN": "arn:aws:memorydb:us-east-1:000111222333:cluster/aquacluster",
        "SnapshotRetentionLimit": 0,
        "MaintenanceWindow": "tue:06:00-tue:07:00",
        "SnapshotWindow": "04:00-05:00",
        "ACLName": "open-access",
        "AutoMinorVersionUpgrade": true
    }
];

const createCache = (clusters, logGroupErr) => {
    return {
        memorydb: {
            describeClusters: {
                'us-east-1': {
                    err: logGroupErr,
                    data: clusters
                },
            },
        },
    };
};


describe('memorydbSnapshotRetention', function () {
    describe('run', function () {
        it('should PASS if MemoryDB Cluster for Redis has snapshot retention period set', function (done) {
            const cache = createCache([describeClusters[0]]);
            memorydbSnapshotRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MemoryDB cluster has snapshot retention period set');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MemoryDB Cluster for Redis does not have snapshot retention period set', function (done) {
            const cache = createCache([describeClusters[1]]);
            memorydbSnapshotRetention.run(cache, {} , (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MemoryDB cluster does not have snapshot retention period set');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no No MemoryDB Cluster found', function (done) {
            const cache = createCache([]);
            memorydbSnapshotRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No MemoryDB clusters found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MemoryDB Clusters', function (done) {
            const cache = createCache(null, { message: "Unable to list MemoryDB clusters" });
            memorydbSnapshotRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

    });
}); 
