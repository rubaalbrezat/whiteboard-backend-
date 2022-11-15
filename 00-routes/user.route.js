'use strict';

const express = require('express');
const { basicAuth } = require('../01-middlewares/basicAuth');
const { bearerAuth } = require('../01-middlewares/bearerAuth');
const router = express.Router();
const { checkUser } = require('../01-middlewares/checkUser');
const { userModel } = require('../03-models');



router.post('/signup', checkUser, signup);
router.post('/signin', basicAuth, signin);
router.get('/users', bearerAuth, getUsers);

async function signup(req, res, next) {
  try {
    let user = await userModel.create(req.body);
    res.status(200).send(user);
  } catch (err) {
    next(`Error inside signup function : ${err}`);
  }
}

async function signin(req, res, next) {
  try {
    let info = {
      user: {
        _id: req.signedUser.id,
        username: req.signedUser.username,
        role: req.signedUser.role,
        capabilities: req.signedUser.capabilities
      },
      token: req.signedUser.token,
    }
    res.status(200).send(info);
  } catch (err) {
    next(`Error inside signin function : ${err}`);
  }
}

async function getUsers(req, res, next) {
  let users = await userModel.findAll();
  res.status(200).send(users);
}
module.exports = router;