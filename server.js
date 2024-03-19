require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const { validationResult } = require("express-validator");
const {
  loginSchema,
  signUpSchema,
} = require("./middlewares/validations/schema");
const validateToken = require("./middlewares/authentication/authJwtVerify");
const { generateToken } = require("./middlewares/authentication/jwt");
const app = express();
const PORT = process.env.PORT;

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {});
const db = mongoose.connection;

// Define user schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  mobile: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

app.use(bodyParser.json());
app.use(cors());

// Signup API
app.post("/api/signup", signUpSchema, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { firstName, lastName, mobile, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User already exists with the given email" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      firstName,
      lastName,
      mobile,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// SignIn API
app.post("/api/signin", loginSchema, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    let { email: reqEmail, password: reqPassword } = req.body;

    // Check if user exists
    const result = await User.findOne({ email: reqEmail });
    if (!result) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(reqPassword, result.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    const token = generateToken(result._id, process.env.JWT_SECRET_KEY, "1h");
    const user = {};
    user.id = result._id;
    user.firstName = result.firstName;
    user.lastName = result.lastName;
    user.email = result.email;
    user.mobile = result.mobile;
    res.json({ token, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/profile", validateToken, async (req, res) => {
  const user = await User.findById(req?.user?.id, { password: 0 });
  if (!user) {
    return res.status(404).json({ message: "User does not exists" });
  }

  res.status(200).json({ message: "success", user });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
