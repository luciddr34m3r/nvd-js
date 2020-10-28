var Ajv = require('ajv');

const cveSchema = require('../schemas/cve.json');
const nvdSchema = require('../schemas/nvd.json');
const metadataSchema = require('../schemas/metadata.json');

let ajv = new Ajv();

const validateMetadata = ajv.compile(metadataSchema);

ajv.addSchema(require('../schemas/cvss-v3.json'));
ajv.addSchema(require('../schemas/cvss-v2.json'));

const validateCve = ajv.compile(cveSchema);
const validateNvd = ajv.compile(nvdSchema);

module.exports = {
    validateMetadata,
    validateCve,
    validateNvd,
};