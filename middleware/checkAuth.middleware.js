const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
   const token = req.header("Authorization");
   if ( ! token) return res.status(400).send("Access Denied!, no token entered");

   try {
      const verified = jwt.verify(token.replace('Bearer ', ''), process.env.jwtSecret);
      req.user = verified;
      next();
    } catch (err) {
        res.status(400).send({ 
            error: "Auth failed" 
        });
    }
};