const fs = require('fs');
const path = require('path');
const Papa = require('papaparse');

function loadCSV(filename) {
  try {
    const filePath = path.isAbsolute(filename) ? filename : path.join(__dirname, '..', '..', 'data', filename);
    const fileContents = fs.readFileSync(filePath, 'utf8');
    const parsed = Papa.parse(fileContents, {
      header: true,
      skipEmptyLines: true,
    });
    return parsed.data;
  } catch (error) {
    console.error(`Error loading CSV file ${filename}:`, error.message);
    return [];
  }
}

function loadJSON(filename) {
  try {
    const filePath = path.isAbsolute(filename) ? filename : path.join(__dirname, '..', '..', 'data', filename);
    const fileContents = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(fileContents);
  } catch (error) {
    console.error(`Error loading JSON file ${filename}:`, error.message);
    return null;
  }
}

module.exports = {
  loadCSV,
  loadJSON,
};
