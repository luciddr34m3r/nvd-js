const axios = require('axios');
const { ungzip } = require('node-gzip');
var Ajv = require('ajv');

// Schema validators
const {
  validateMetadata,
  validateCve,
  validateNvd,
} = require('./util/validators');

const BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-';

const CVE_CATEGORIES = {
    RECENT: 'recent',
    MODIFIED: 'modified',
};

// TODO: Need to figure out the proper docstrings for these
class InvalidCVECategory extends Error {}
class InvalidNVDObject extends Error {}
class NVDUnexpectedResponse extends Error {}
class NVDResponseTimeout extends Error {}

/**
 * 
 * Checks to see if a supplied category is valid.
 * @param {string} category - A cstring that contains the category of vulnerability metadata. 
 * @return {boolean} - Returns true if the input is a valid vulnerability category
 * 
 */
const isValidCategory = (category) => {
  try {
    if (parseInt(category) >= 2002 && parseInt(category) < 2100) {
      return true;
    }
  } catch (error) {}

  return Object.values(CVE_CATEGORIES).includes(category);
}

/**
 * Returns the metadata fields from the appropriate CVE category.
 * @param {string} category - The category to get metadata for. Could be 'recent', 'modified', or the year of the cve list.
 * @return {Object} - A dictionary of the metafata fields for a CVE category from NVD.
 * @throws {InvalidCVECategory} - Supplied category is invalid.
 * @throws {NVDUnexpectedResponse} - The response from NVD had unexpected content.
 */
const getNvdListMetadata = async (category) => {
    if(!isValidCategory(category)) {
      throw new InvalidCVECategory("The supplied category is invalid.");
    }

    // TODO: Validate before returning.
    const url = `${ BASE_URL }${ category }.meta`;
    let data;
    let metadata = {};
    
    try {
      const res = await axios.get(url);
      data = res.data;
    } catch (error) {
      throw new NVDResponseTimeout("No or invalid response from NVD.");
    }
    
    try {
      data.split('\r\n')
      .forEach(pair => {
        let [key, ...value] = pair.split(':');
        value = value.join(":");
        if (key !== '') {
          metadata[key.trim()] = value.trim();
        }
      });
      
      metadata.size = parseInt(metadata.size, 10);
      metadata.zipSize = parseInt(metadata.zipSize, 10);
      metadata.gzSize = parseInt(metadata.gzSize, 10);
    } catch (error) {
      throw new NVDUnexpectedResponse(error.message)
    }

    if(!validateMetadata(metadata)) {
      throw new NVDUnexpectedResponse("NVD response failed to validate.");
    }

    return metadata;
    
  };

/**
 * 
 * Gets a the requested NVD feed data object.
 * @param {string} category - The category to get metadata for. Could be 'recent', 'modified', or the year of the cve list.
 * @return {Array} - Returns an array of CVEs from the specified category on NVD.
 * @throws {InvalidCVECategory} - Throws this exception if the supplied category is invalid.
 * 
 */
const getNvdFeed = async (category) => {
  let data;

  if(!isValidCategory(category)) {
    throw new InvalidCVECategory("The supplied category was invalid.")
  }

  const url = `${ BASE_URL }${ category }.json.gz`;

  try {
    await axios.get(url, {responseType: "arraybuffer"}).then(async (res) => {
      await ungzip(Buffer.from(res.data, 'binary')).then((cves) => {
        data = JSON.parse(cves.toString());
        return true;
      }).catch(() => {
        // TODO: Better logging. Former logging statement is preserved below
        //functions.logger.info(error);
      });
      return true;
   });
    
  } catch (error) {
    // TODO: Better logging. Former logging statement is preserved below
    //functions.logger.info("Error processing getRecentCves");
    //functions.logger.info(error);
  }
  
  // TODO: data could potentially be empty due to poor error handling
  return data;
  
};

/**
 * Returns a list of CVE objects from an NVD data feed object.
 * @param {Object} feed - An NVD database json object as returned from getNvdListMetadata().
 * @returns {Array} - An array of CVE elements.
 * @throws {InvalidNVDObject} - Throws this exception if the supplied NVD data feed is invalid.
 */
const getCvesFromNvdFeed = (feed) => {
  if(!validateNvd(feed)) {
    throw new InvalidNVDObject("Invalid NVD object provided.");
  }

  return feed.CVE_Items;
};

module.exports = {
    getNvdListMetadata,
    getNvdFeed,
    getCvesFromNvdFeed,
    isValidCategory,
    CVE_CATEGORIES,
    InvalidCVECategory,
    InvalidNVDObject,
};