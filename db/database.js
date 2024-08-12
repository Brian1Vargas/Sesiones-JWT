// database.js
const Database = require('./db');
const dbConfig = require('./dbConfig');

const db = new Database(dbConfig);

module.exports = db;
