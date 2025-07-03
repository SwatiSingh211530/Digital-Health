const express = require("express");
const multer = require("multer");
const auth = require("../middleware/auth");
const { uploadFile } = require("../controllers/fileController");

const router = express.Router();

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + "_" + file.originalname);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    cb(null, true); // Accept all file types
  }
});

router.post("/", auth, upload.single("file"), uploadFile);

module.exports = router;
