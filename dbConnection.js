require("dotenv").config();

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_pw = process.env.MONGODB_PASSWORD;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_pw}@${mongodb_host}/retryWrites=true`;
var database = new MongoClient(atlasURI, {});
module.exports = {database};