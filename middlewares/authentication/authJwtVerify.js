const { verifyToken } = require("./jwt");
module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    const verification = verifyToken(token, process.env.JWT_SECRET_KEY);

    if (!verification) {
      return res.status(401).json({ message: "Invalid Token" });
    }
    req.user = verification;
    next();
  } else {
    return res.status(400).json({ message: "Token required" });
  }
};
