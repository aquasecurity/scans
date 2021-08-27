// Source: https://www.alibabacloud.com/global-locations

var regions = [
    'cn-hangzhou',            // China (Hangzhou)
    'cn-shanghai',            // China (Shanghai)
    'cn-qingdao',             // China (Qingdao)
    'cn-beijing',             // China (Beijing)
    'cn-zhangjiakou',         // China (Zhangjiakou)
    'cn-huhehaote',           // China (Hohhot)
    'cn-wulanchabu',          // China (Ulanqab)
    'cn-shenzhen',            // China (Shenzhen)
    'cn-heyuan',              // China (Heyuan)
    'cn-chengdu',             // China (Chengdu)
    'cn-hongkong',            // China (Hong Kong)
    'cn-guangzhou',           // China (Guangzhou)
    'ap-southeast-1',         // Singapore
    'ap-southeast-2',         // Australia (Sydney)
    'ap-southeast-3',         // Malaysia (Kuala Lumpur)
    'ap-southeast-5',         // Indonesia (Jakarta)
    'ap-northeast-1',         // Japan (Tokyo)
    'ap-south-1',             // India (Mumbai)
    'eu-central-1',           // Germany (Frankfurt)
    'eu-west-1',              // UK (London)
    'us-west-1',              // US (Silicon Valley)
    'us-east-1',              // US (Virginia)
    'me-east-1',              // UAE (Dubai)
];

module.exports = {
    default: ['cn-hangzhou'],
    all: regions,
    ecs: regions,
    polardb: regions,
    ram: ['cn-hangzhou'],
    vpc: regions,
    rds: regions,
    sts: ['cn-hangzhou'],
    oss: ['cn-hangzhou'],
    kms: regions,
    actiontrail: regions,
    ack: ['cn-hangzhou'],
    apigateway: regions,
};
