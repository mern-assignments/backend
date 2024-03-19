const { check } = require("express-validator");

const loginSchema = [
  check("email").isEmail().withMessage("Invalid email"),
  check("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long"),
];
const signUpSchema = [
  ...loginSchema,
  check("firstName").notEmpty().withMessage("First name is required"),
  check("lastName").notEmpty().withMessage("Last name is required"),
  check("mobile").notEmpty().withMessage("Mobile number is required"),
];

module.exports = { loginSchema, signUpSchema };
