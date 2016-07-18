var express = require('express');
var router = express.Router();

// Import the user class
var User = require('../models/user')

/* Signup page. GET */
router.get('/', function(req, res) {
  res.render('signup', {
    user: req.user
  });
});

/* Signup page. POST */
router.post('/', function(req, res) {
  // Recovery the data from the post
  var user = new User({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password
    });
  // Saving the data into the data base
  user.save(function(err) {
    // Then, we login in the system.
    req.logIn(user, function(err) {
      // Finally, redirect the user to the main page
      res.redirect('/');
    });
  });
});

module.exports = router;
