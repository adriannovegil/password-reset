var express = require('express');
var router = express.Router();

/* Logout page. GET */
router.get('/', function(req, res){
  req.logout();
  res.redirect('/');
});

module.exports = router;
