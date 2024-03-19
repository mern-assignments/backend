const jwt = require("jsonwebtoken");
const verifyToken = (token, secretKey) => {
  return jwt.verify(token, secretKey, (err, res) => {
    if (err) {
      return false;
    }
    return res;
  });
};

const generateToken = (id, secretKey, expiresIn = "1h") => {
  return jwt.sign({ id }, secretKey, {
    expiresIn,
  });
};

module.exports = { verifyToken, generateToken };
