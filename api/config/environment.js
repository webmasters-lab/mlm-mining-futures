// Environment configuration for MLM Mining Futures

module.exports = {
    development: {
        apiBaseUrl: 'http://localhost:3000/api',
        dbConnectionString: 'mongodb://localhost:27017/mlm-mining-futures',
        logging: true
    },
    production: {
        apiBaseUrl: 'https://api.mlm-mining-futures.com/api',
        dbConnectionString: 'mongodb://prod-db:27017/mlm-mining-futures',
        logging: false
    },
    test: {
        apiBaseUrl: 'http://localhost:3001/api',
        dbConnectionString: 'mongodb://localhost:27017/mlm-mining-futures-test',
        logging: true
    }
};