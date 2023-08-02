const sendEmail = require('./sendEmail');

const sendResetPasswordEmail = async ({ origin, name, email, token }) => {
  const resetUrl = `${origin}/user/reset-password?token=${token}&email=${email}`;
  const message = `<p>Please reset your password by clicking on the following link: <a href=${resetUrl}>Reset Password</a></p>`;

  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `<h4>Hello ${name}</h4>
    ${message}`,
  });
};

module.exports = sendResetPasswordEmail;
