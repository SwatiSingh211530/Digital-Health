const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// 👉 OTP Send
exports.sendOTP = async (req, res) => {
  const { mobile } = req.body;
  if (!mobile) return res.status(400).json({ success: false, message: "Mobile number required" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  let user = await User.findOne({ mobile });
  if (!user) {
    user = new User({ mobile });
  }

  user.otp = otp;
  user.otpExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
  await user.save();

  // TODO: Integrate SMS gateway here (e.g., Twilio, Fast2SMS)
  console.log(`OTP sent to ${mobile}: ${otp}`);

  res.json({ success: true, message: "OTP sent successfully" });
};

// 👉 OTP Verify
exports.verifyOTP = async (req, res) => {
  const { mobile, otp } = req.body;
  if (!mobile || !otp) return res.status(400).json({ success: false, message: "Mobile and OTP required" });

  const user = await User.findOne({ mobile });
  if (!user || user.otp !== otp || user.otpExpiresAt < Date.now()) {
    return res.status(401).json({ success: false, message: "Invalid or expired OTP" });
  }

  user.otp = null;
  user.otpExpiresAt = null;
  await user.save();

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

  res.json({ success: true, message: "OTP verified", token });
};

// 🔐 Existing register
exports.register = async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ email, password: hashed });
  res.redirect("/");
};

// 🔐 Existing login
exports.login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).send("Invalid credentials");

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
};
