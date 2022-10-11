'use strict';

const express = require('express');
const { postModel, commentModel } = require('../03-models');
const { bearerAuth } = require('../01-middlewares/bearerAuth');
const { acl } = require('../01-middlewares/acl');

const router = express.Router();


router.post('/post', bearerAuth, acl('create'), Addpost);
router.get('/post', bearerAuth, acl('read'), getPosts);
router.get('/post/:id', bearerAuth, acl('read'), getOnePost);
router.put('/post/:id', bearerAuth, acl('update'), updatePost);
router.delete('/post/:id', bearerAuth, acl('delete'), deletePost);



async function Addpost(req, res, next) {
  try {
    
    const postData = {
      title: req.body.title,
      content: req.body.content,
      userId: req.user.id,
    }
    let createdPost = await postModel.create(postData);
    res.status(201).json(createdPost);
  } catch (err) {
    next(`Error inside Addpost function : ${err}`);
  }
}

async function getPosts(req, res, next) {
  try {
    let posts = await postModel.findAll({ include: commentModel });
    res.status(200).send(posts);
  } catch (err) {
    next(`Error inside getPosts function : ${err}`);
  }
}

async function getOnePost(req, res, next) {
  try {
    let id = req.params.id;
    let post = await postModel.findOne({ where: { id } });
    if (post === null) {
      res.status(204).send(`no post with match id`);
    } else {
      res.status(200).send(post);
    }
  } catch (err) {
    next(`Error inside getOnePost function : ${err}`);
  }
}

async function updatePost(req, res, next) {
  try {
    let id = req.params.id;
    let newPostData = req.body;  //req.body : {"title":"any new data", "content":"any new data"}
    await postModel.update(newPostData, { where: { id } });
    let updatedPost = await postModel.findOne({ where: { id } });
    res.status(200).send(updatedPost);
  } catch (err) {
    next(`Error inside updatePost function : ${err}`);
  }
}

async function deletePost(req, res, next) {
  try {
    let id = req.params.id;
    await postModel.destroy({ where: { id } });
    res.status(202).end();
  } catch (err) {
    next(`Error inside deletePost function : ${err}`);
  }
}




module.exports = router;