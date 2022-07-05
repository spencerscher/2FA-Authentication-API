const speakeasy = require('speakeasy');
const jwt = require('jsonwebtoken');
const User = require('../db/models/user');

let parseJwt = (token) => {
    //decode jwt payload
    const payload = token.split('.')[1];
    const decodedPayload = Buffer.from(payload, 'base64').toString('ascii');
    const jsonPayload = JSON.parse(decodedPayload);
    return jsonPayload;
}

let getUserPrivateKey = async (token) => {
    try {
        let payload = parseJwt(token)
        const user = await User.findOne(
            { _id: payload.dataInToken._id }
        );
        if (!user) {
            return res.status(401).json({
                message: 'Invalid token'
            });
        }
        return user;
    }
    catch (err) {
        console.log(err)
    }
}

let verifyOTP = async (otp, req, res) => {
    const verified = speakeasy.totp.verify({
        secret: req.user.secretKey,
        encoding: 'base32',
        token: otp
    });
    if (!verified) {
        return res.status(400).json({
            message: 'OTP is incorrect'
        });
    }
    else {
        const dataInToken = {
            _id: req.user._id,
            email: req.user.email,
            multiFactorEnabled: req.user.multiFactorEnabled,
            isSecondFactorAuthed: true
        };
        const token = jwt.sign(
            { dataInToken },
            req.privateKey,
            { expiresIn: '1h' }
        );
        res.status(200).json({
            message: 'User logged in successfully',
            token: token
        });
    }
}

module.exports = { parseJwt, getUserPrivateKey, verifyOTP };