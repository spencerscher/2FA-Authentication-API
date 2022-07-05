const jwt = require('jsonwebtoken');
const utils = require('../utils/utils.jwt')

let authentication = async (req, res, next) => {
    //if the user is hitting the register endpoint, then we don't need to check if they are logged in
    if (req.originalUrl.startsWith('/account/register') ||
        req.originalUrl.startsWith('/account/login') ||
        req.originalUrl.startsWith('/account/reset-password')) {
        return next();
    }

    //if there is no auth-token header, return an error
    if (!req.headers['auth-token'] ||
        req.headers['auth-token'] === '') {
        return res.status(401).json({
            message: 'No token provided'
        });
    }

    try {
        const token = req.headers['auth-token'];

        const user = await utils.getUserPrivateKey(token);
        const privateKey = user.password;
        req.user = user;

        if (req.originalUrl.startsWith('/account/authenticate')) {
            req.privateKey = privateKey.toString();
            return next();
        }

        jwt.verify(
            token,
            privateKey,
            (err, decoded) => {
                console.log(decoded)
                if (err) {
                    return res.status(401).json({
                        message: 'Invalid token.'
                    });
                }
                //check if isSecondFactorAuthed is set to false
                if (!decoded.dataInToken.isSecondFactorAuthed &&
                    decoded.dataInToken.multiFactorEnabled) {
                    console.log(decoded)
                    return res.status(401).json({
                        message: '2FA is required.'
                    });
                }
                else {
                    req.privateKey = privateKey.toString();
                    next();
                }
            });
    }
    catch (err) {
        console.log(err)
    }
}

module.exports = authentication;