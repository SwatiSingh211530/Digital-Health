const fs = require("fs");
const { cloudinary } = require("../config/cloudinary");
const PatientDetails = require("../models/File");

exports.uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: "No file uploaded" });
    }

    const { name, age, address, contact, email, purpose } = req.body;

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: "patient_files",
    });

    // Delete local temp file asynchronously
    fs.unlink(req.file.path, (err) => {
      if (err) console.error("Temp file delete failed:", err);
    });

    // Save metadata to MongoDB
    const newFile = await PatientDetails.create({
      filename: req.file.filename,
      imageURL: result.secure_url,
      name,
      age,
      address,
      contact,
      email,
      purpose,
      user: req.user.id,      // <-- FIXED here: pass only user id string
      uploadedAt: new Date(),
    });

    console.log("📦 Saved patient record:", newFile);

    // Respond success
    res.json({
      success: true,
      message: "File uploaded successfully",
      previewURL: newFile.imageURL,
      patient: {
        name,
        age,
        contact,
        email,
        purpose,
      },
    });
  } catch (err) {
    console.error("❌ Upload error:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: err.message,
    });
  }
};
