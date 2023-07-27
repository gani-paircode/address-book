const express = require('express');
const router = express.Router();
const uuidv4 = require("uuid");
const SHA256 = require("crypto-js/sha256");
const _ = require("lodash");
const { LOGIN_FILE_PATH, COOKIES_NAME } = require('../constants/general');
const { readDataFromFile, writeDataToFile } = require('../model/files');

const getHashedPassword = (plainPassword) => SHA256(plainPassword).toString();
const generateLoginToken = (phoneNumber) => {
  const p1 = `${Math.random() * phoneNumber}`.replace(".", "");
  const p2 = `${Math.random() * phoneNumber}`.replace(".", "");
  const batakaa = [p1, ...uuidv4.v4().split("-"), p2, ...uuidv4.v4().split("-")];
  return _.shuffle(batakaa).join("-");
};

router.post('/v1', async (req, res) => {
  const { phoneNumber, password } = req.body;
  console.log('credentials in login/v1 ', { phoneNumber, password });
  try {
    let users = await readDataFromFile(LOGIN_FILE_PATH);
    const user = users.find((u) => u.phoneNumber === phoneNumber);
    if (!user) {
      res.status(400).send({ message: 'Invalid id or password' });
      return;
    }
    if (user.isActive === false) {
      res.status(400).send({ message: 'User is deactivated. Please contact admin.' });
      return;
    }
 
    const hashedPassword = getHashedPassword(password);
    if (user.hashedPassword !== hashedPassword) {
      res.status(400).send({ message: 'Invalid password' });
      return;
    }
    const loginToken = generateLoginToken(phoneNumber);
    user.token = loginToken;
    res.cookie(COOKIES_NAME.PHONE, phoneNumber); // meaningful only if be and fe are on the same domain
    res.cookie(COOKIES_NAME.TOKEN, loginToken);
    res.cookie('test123', loginToken);
    await writeDataToFile(LOGIN_FILE_PATH, users);
    console.log('------------> ', { loginToken, phoneNumber });
    res.json({ loginToken, phoneNumber });
    return;
} catch (error) {
  console.log('Error -> ', error);
    res.status(500).send({ message: 'Internal Server Error' });
    return;
}
});


module.exports = router;
