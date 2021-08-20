var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./autoscaleMinCpuUtilization');

const createCache = (instanceData, instanceGroupsError, autoScalersError) => {
    return {
        instanceGroups: {
            aggregatedList: {
                'global': {
                    data: instanceData.instanceGroups,
                    err: instanceGroupsError
                }
            }
        },
        autoscalers: {
            aggregatedList: {
                'global': {
                    data: instanceData.autoscalers,
                    err: autoScalersError
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'tets-proj'
                }
            }
        }
    }
};

describe('autoscaleMinCpuUtilization', function () {
    describe('run', function () {

        it('should give unknown if an instance group error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instance groups');
                done()
            };

            const cache = createCache(
                {
                    instanceGroups: [],
                    autoscalers: []
                },
                ['error'], null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no instance groups found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instance groups found');
                done()
            };

            const cache = createCache(
                {
                    instanceGroups: [],
                    autoscalers: []
                },
                null, null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give unknown if an autoscaler error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query autoscalers');
                done()
            };

            const cache =  createCache(
                {
                    instanceGroups: [
                        {
                            instanceGroups: [
                                {
                                    creationTimestamp: '2021-08-16T01:24:42.747-07:00',
                                    name: 'instance-group-1',
                                    description: "This instance group is controlled by Instance Group Manager 'instance-group-1'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                                    zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                    kind: 'compute#instanceGroup'
                                }
                            ]
                        }
                    ]
                }, null, ['error']
            );


            plugin.run(cache, {}, callback);
        });

        it('should pass no autoscalers found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No autoscalers found');
                done()
            };

            const cache = createCache(
                {
                    instanceGroups: [
                        {
                            instanceGroups: [
                                {
                                    creationTimestamp: '2021-08-16T01:24:42.747-07:00',
                                    name: 'instance-group-1',
                                    description: "This instance group is controlled by Instance Group Manager 'instance-group-1'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                                    zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                    kind: 'compute#instanceGroup'
                                }
                            ]
                        }
                    ],
                    autoscalers: []
                },
                null, null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if instance group does not have desired minimum cpu utilization target', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance group does not have desired minimum cpu utilization target');
                done()
            };

            const cache = createCache(
                {
                    instanceGroups: [
                        {
                            instanceGroups: [
                                {
                                    creationTimestamp: '2021-08-16T01:24:42.747-07:00',
                                    name: 'instance-group-1',
                                    description: "This instance group is controlled by Instance Group Manager 'instance-group-1'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                                    zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                    kind: 'compute#instanceGroup'
                                }
                            ]
                        }
                    ],
                    autoscalers: {
                            'global': {
                                autoscalers: [
                                    {
                                        creationTimestamp: '2021-08-16T01:24:57.502-07:00',
                                        name: 'instance-group-1',
                                        autoscalingPolicy: { cpuUtilization: { utilizationTarget: 0.001, predictiveMethod: 'NONE' } },
                                        zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                        status: 'ACTIVE',
                                        kind: 'compute#autoscaler'
                                    }
                                ]
                            }
                    }
                },
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if instance group has desired minimum cpu utilization target', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Instance group has desired minimum cpu utilization target');
                done()
            };

            const cache = createCache(
                {
                    instanceGroups: [
                        {
                            instanceGroups: [
                                {
                                    creationTimestamp: '2021-08-16T01:24:42.747-07:00',
                                    name: 'instance-group-1',
                                    description: "This instance group is controlled by Instance Group Manager 'instance-group-1'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                                    zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                    kind: 'compute#instanceGroup'
                                }
                            ]
                        }
                    ],
                    autoscalers: {
                            'global': {
                                autoscalers: [
                                    {
                                        creationTimestamp: '2021-08-16T01:24:57.502-07:00',
                                        name: 'instance-group-1',
                                        autoscalingPolicy: { cpuUtilization: { utilizationTarget: 0.6, predictiveMethod: 'NONE' } },
                                        zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                        status: 'ACTIVE',
                                        kind: 'compute#autoscaler'
                                    }
                                ]
                            }
                    }
                },
                null
            );

            plugin.run(cache, {}, callback);
        })
        it('should pass if no autoscaling policies found for instance group', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('No auto scaling policies found for this instance group');
                done()
            };

            const cache = createCache(
                {
                    instanceGroups: [
                        {
                            instanceGroups: [
                                {
                                    creationTimestamp: '2021-08-16T01:24:42.747-07:00',
                                    name: 'instance-group-1',
                                    description: "This instance group is controlled by Instance Group Manager 'instance-group-1'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                                    zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                    kind: 'compute#instanceGroup'
                                }
                            ]
                        }
                    ],
                    autoscalers: {
                            'global': {
                                autoscalers: [
                                    {
                                        creationTimestamp: '2021-08-16T01:24:57.502-07:00',
                                        name: 'instance-group-2',
                                        autoscalingPolicy: { cpuUtilization: { utilizationTarget: 0.6, predictiveMethod: 'NONE' } },
                                        zone: 'https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a',
                                        status: 'ACTIVE',
                                        kind: 'compute#autoscaler'
                                    }
                                ]
                            }
                    }
                },
                null
            );


            plugin.run(cache, {}, callback);
        })

    })
});