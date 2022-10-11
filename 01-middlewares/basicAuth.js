'use strict';

const { userModel } = require('../03-models');
const base64 = require('base-64');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

async function basicAuth(req, res, next) {
  try {
    let basicAuth = req.headers.authorization;        
    let encodedData = basicAuth.split(' ')[1];      
    let decodedData = base64.decode(encodedData);     
    let [username, password] = decodedData.split(':');
    let user = await userModel.findOne({ where: { username } });
    if (user) {
      let checkPassword = await bcrypt.compare(password, user.password);
      if (checkPassword) {
        const token = jwt.sign({ ruba: user.username }, process.env.SECRET);
        user.token = token;
        user.role = user.role;
        req.signedUser = user;
        
        next();
      } else {
        res.status(403).send('Password is incorrect');
      }
    } else {
      res.status(203).send(`No user found SIGNUP`);
    }
  } catch (err) {
    next(`Error inside basicAuth middleware : ${err}`);
  }
};



module.exports = { basicAuth };