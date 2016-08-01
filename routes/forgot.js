var express = require('express');
var router = express.Router();

var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');

// Import the user class
var User = require('../models/user')

/* Forgot page. GET */
router.get('/', function(req, res) {
  res.render('forgot', {
    user: req.user
  });
});

/* Forgot page. POST */
router.post('/', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      /*var smtpTransport = nodemailer.createTransport('SMTP', {
        service: 'SendGrid',
        auth: {
          user: '!!! YOUR SENDGRID USERNAME !!!',
          pass: '!!! YOUR SENDGRID PASSWORD !!!'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'passwordreset@demo.com',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });*/

      console.log('[INFO] TO....: ' + user.email);
      console.log('[INFO] FROM..: ' + "passwordreset@demo.com");
      console.log('[INFO] TEXT..: ');
      console.log('You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
        'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
        'http://' + req.headers.host + '/reset/' + token + '\n\n' +
        'If you did not request this, please ignore this email and your password will remain unchanged.\n');
      console.log('[INFO] END');

      // Requeste message
      req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
      done(null, 'done');

    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});

module.exports = router;
