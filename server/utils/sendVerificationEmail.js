const sendEmailEthereal = require('./sendEmail');

const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const verifyEmailLink = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;
  const message = `<p>Please confirm your email by clicking the following link: <a href=${verifyEmailLink}>verify email</a></p>`;

  return sendEmailEthereal({
    to: email,
    subject: 'Email Confirmation',
    html: `<h4>hello ${name}</h4>
     ${message}`,
  });
};

module.exports = sendVerificationEmail;
