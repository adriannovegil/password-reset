var express = require('express');
var router = express.Router();

var async = require('async');
var nodemailer = require('nodemailer');

// Import the user class
var User = require('../models/user')

/* Reset page.  GET */
router.get('/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});

/* Reset page.  POST */
router.post('/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          req.logIn(user, function(err) {
            done(err, user);
          });
        });
      });
    },
    function(user, done) {
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
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });*/

      console.log('[INFO] TO....: ' + user.email);
      console.log('[INFO] FROM..: ' + "passwordreset@demo.com");
      console.log('[INFO] TEXT..: ');
      console.log('Hello,\n\n' +
        'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n');
      console.log('[INFO] END');

      // Requeste message
      req.flash('success', 'Success! Your password has been changed.');
      done(null, 'done');

    }
  ], function(err) {
    res.redirect('/');
  });
});

module.exports = router;
