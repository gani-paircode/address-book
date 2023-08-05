const uuidv4 = require("uuid");
const { readDataFromFile } = require('../model/files');
const { COOKIES_NAME, LOGIN_FILE_PATH } = require("../constants/general");

const authenticateReq = async (req, res, next) => {
    /* why we need to rely on headers ? bcz be and fe are on different domains */
    const ckToken = req.cookies[COOKIES_NAME.TOKEN] || req.headers[COOKIES_NAME.TOKEN];
    const ckuserPn = req.cookies[COOKIES_NAME.PHONE] || req.headers[COOKIES_NAME.PHONE];
    try {
        const loginUsers = await readDataFromFile(LOGIN_FILE_PATH);
        const index = loginUsers.findIndex(u => u.phoneNumber === ckuserPn && u.token === ckToken);
        if (index === -1) {
            res.cookie(COOKIES_NAME.PHONE, '');
            res.cookie(COOKIES_NAME.TOKEN, '');
            res.status(403).send({ 
                message: 'Unauthorized request. Please do login first.',
                errorCode: 20403,
            });
            return;
        }
        const user = loginUsers[index];
        if (user.isActive === false) {
            res.cookie(COOKIES_NAME.PHONE, '');
            res.cookie(COOKIES_NAME.TOKEN, '');
            res.status(403).send({ 
                message: 'User is not active at this time. Please contact admin.',
                errorCode: 20403,
            });
            return;
        }
        next();
    } catch (error) {
        console.log('Error in authenticateReq ', error);
        res.status(500).send({ message: 'Internal Server Error' });
    }
}

const injectReqId = (req, res, next) => {
    req.requestId = `${uuidv4.v4()}-${uuidv4.v4()}`;
    res.setHeader("X-request-id", req.requestId);
    next();
};

module.exports = {
    authenticateReq,
    injectReqId,
}