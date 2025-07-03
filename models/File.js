const mongoose = require("mongoose");

const FileSchema = new mongoose.Schema({
  filename: String,
  imageURL: String,
  name: String,
  age: Number,
  address: String,
  contact: String,
  email: String,
  purpose: String,
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("File", FileSchema);
