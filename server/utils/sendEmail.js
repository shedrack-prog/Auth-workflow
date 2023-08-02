const nodeMailerConfig = require('./nodeMailerConfig');
const nodemailer = require('nodemailer');

const sendEmailEthereal = async ({ to, subject, html }) => {
  const transporter = nodemailer.createTransport(nodeMailerConfig);

  return transporter.sendMail({
    from: '"Shedrack Tobiloba" <usheddy07@gmail.com>',
    to,
    subject,
    html,
  });
};

module.exports = sendEmailEthereal;
