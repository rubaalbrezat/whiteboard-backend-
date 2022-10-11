'use strict';

const bcrypt = require('bcrypt');
const { userModel } = require('../03-models');

async function checkUser(req, res, next) {
  try {
    const { email, username, password } = req.body; 
    let checkUsername = await userModel.findOne({ where: { username } });
    let checkemail = await userModel.findOne({ where: { email } });
    if (checkUsername) {
      res.status(409).send(`Username is taken`);
    } else if (checkemail) {
      res.status(409).send(`Email is taken`);
    } else {
      let hashedPassword = await bcrypt.hash(password,10);
      req.body.password = hashedPassword;
      next();
    }
  } catch (err) {
    next(`Error inside checkUser middleware : ${err}`);
  }
}



module.exports = { checkUser };