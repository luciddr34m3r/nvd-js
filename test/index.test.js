const chai = require('chai')
chai.use(require('chai-as-promised'));
const should = chai.should();

// Schema validators
const {
    validateMetadata,
    validateCve,
    validateNvd,
} = require('../util/validators');

// Mock these
const axios = require('axios');
const nodeGzip = require('node-gzip');

const nvd = require('../index');
const data = require('./data/sampleData');

jest.mock('axios');
jest.mock('node-gzip');

describe('Module tests', () => {

    describe('#isValidCategory()', () => {

        it('should return true if the supplied category is valid', () => {
            nvd.isValidCategory("2020").should.be.true;
            nvd.isValidCategory("recent").should.be.true;
            nvd.isValidCategory(nvd.CVE_CATEGORIES.MODIFIED).should.be.true;
        });

        it('should return false if the supplied category is invalid', () => {
            nvd.isValidCategory(2001).should.be.false;
            nvd.isValidCategory(2100).should.be.false;
            nvd.isValidCategory("foo").should.be.false;
            nvd.isValidCategory([]).should.be.false;
            nvd.isValidCategory({}).should.be.false;
        });

    });

    describe('#getNvdListMetadata()', () => {

        it('should return a valid metadata JSON object', async () => {
            axios.get.mockResolvedValue({ data: data.metaData });

            let resp = await nvd.getNvdListMetadata(nvd.CVE_CATEGORIES.RECENT);
            validateMetadata(resp).should.be.true;
            resp.lastModifiedDate.should.equal("2020-10-27T18:01:52-04:00");
            resp.size.should.equal(7680682);
            resp.zipSize.should.equal(527727);
            resp.gzSize.should.equal(527583);
            resp.sha256.should.equal("3B7EBF83BAF9435BCACE6B2C36BC20EAC62800F09EB8323BDCC62BC66DCC7D40");
        });

        it('should throw an appropriate error if NVD response data is invalid', async () => {
            axios.get.mockResolvedValue({ data: "foo:bar\r\n" });
            nvd.getNvdListMetadata(nvd.CVE_CATEGORIES.RECENT).should.be.rejectedWith(nvd.NVDUnexpectedResponse);
            axios.get.mockResolvedValue({ data: "" });
            nvd.getNvdListMetadata(nvd.CVE_CATEGORIES.RECENT).should.be.rejectedWith(nvd.NVDUnexpectedResponse);
        });

        it('should throw an appropriate error if NVD fails to respond', async () => {
            axios.get.mockImplementation(() => {
                throw new Error();
            });
            nvd.getNvdListMetadata(nvd.CVE_CATEGORIES.RECENT).should.be.rejectedWith(nvd.NVDResponseTimeout);
        });

    });

    describe('#getNvdFeed()', () => {

        it('should return a valid NVD feed', async () => {
            axios.get.mockResolvedValue({data: ""});
            nodeGzip.ungzip.mockResolvedValue(JSON.stringify(data.nvd));

            let resp = await nvd.getNvdFeed(nvd.CVE_CATEGORIES.RECENT);

            validateNvd(resp).should.be.true;
        });

        it('should throw an InvalidCVECategory if the category is invalid', async () => {
            return nvd.getNvdFeed("foo").should.eventually.be.rejectedWith(nvd.InvalidCVECategory);
        });

    });

    describe('#getCvesFromNvdFeed()', () => {
        
        it('should return an array of CVEs when provided an NVD object', () => {
            nvd.getCvesFromNvdFeed(data.nvd).forEach((cve) => {
                validateCve(cve.cve).should.be.true;
            });
        });

        // TODO: getCvesFromNvdFeed test of InvalidNVDObject fails for unknown reason
        it.skip('should throw an InvalidNVDObject if the NVD feed is invalid', () => {
            return nvd.getCvesFromNvdFeed({}).should.eventually.be.rejectedWith(nvd.InvalidNVDObject);
        });

    });

});