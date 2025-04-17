const mongoose = require('mongoose');

// Function to check if a string is a valid ObjectId
function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}


module.exports = isValidObjectId