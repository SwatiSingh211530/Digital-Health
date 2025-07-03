const express = require("express");
const router = express.Router();
const {
  register,
  login,
  sendOTP,
  verifyOTP
} = require("../controllers/authController");

// POST /register
router.post("/register", register);

// POST /login
router.post("/login", login);

// POST /send-otp
router.post("/send-otp", sendOTP);

// POST /verify-otp
router.post("/verify-otp", verifyOTP);

module.exports = router;
