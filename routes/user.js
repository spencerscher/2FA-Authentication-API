var express = require('express');
var router = express.Router();
const dotenv = require('dotenv')
const User = require('../db/models/user')
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const utils = require('../utils/utils.jwt');
const passwordUtil = require('../utils/utils.passwords');
const Reset = require('../db/models/reset');
dotenv.config()
const sgMail = require('@sendgrid/mail')
sgMail.setApiKey(process.env.SENDGRID_API_KEY)


router.post('/register', async (req, res) => {

    //check if username, password, and email are in the response body
    if (!req.body.username ||
        !req.body.password ||
        !req.body.email) {
        return res.status(400).json({
            success: "false",
            message: 'Please provide a username, password, and email'
        });
    }

    try {
        //get the data from the request
        const { username, password, email } = req.body;
        //check if the user already exists
        const isUser = await User.findOne({ username });
        if (isUser) {
            return res.status(400).json({
                success: "false",
                message: 'This username is already taken'
            });
        }

        //check if the email is already in use
        const isEmail = await User.findOne({ email });
        if (isEmail) {
            return res.status(400).json({
                success: "false",
                message: 'This email is already in use'
            });
        }

        const hashedPassword = await passwordUtil.generatePassword(password);
        //hash password and save user
        // const salt = await bcrypt.genSalt(10);
        // const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            username,
            password: hashedPassword,
            email,
            multiFactorEnabled: false,
            secretKey: ''
        });
        await user.save();

        const dataInToken = {
            _id: user._id,
            email: user.email,
            multiFactorEnabled: user.multiFactorEnabled,
            isSecondFactorAuthed: true,
        };

        const token = jwt.sign(
            { dataInToken },
            hashedPassword,
            { expiresIn: '1h' }
        );
        res.status(200).json({
            message: 'User created successfully',
            token: token
        });
    }
    catch (err) {
        res.status(400).json({
            message: err.message
        });
    }
});

router.post('/login', async (req, res) => {
    //get the data from the request
    const { username, password, otp } = req.body;

    //check if the user exists
    const user = await User.findOne({ username });

    if (!user) {
        return res.status(400).json({
            message: 'User does not exist'
        });
    }

    //check if the password is correct
    const verifiedPassword = await passwordUtil.comparePasswords(password, user.password);

    if (!verifiedPassword) {
        return res.status(400).json({
            message: 'Incorrect password'
        });
    }

    //check if 2FA is off on users' account
    if (!user.multiFactorEnabled) {
        const dataInToken = {
            _id: user._id,
            email: user.email,
            multiFactorEnabled: user.multiFactorEnabled,
            isSecondFactorAuthed: true
        };

        //create and assign a token that is valid for 1 hour
        const token = jwt.sign(
            { dataInToken },
            user.password,
            { expiresIn: '1h' }
        );

        //send the token to the client
        return res.header('auth-token', token).json({
            message: 'Login successful',
            token: token
        });
    }

    //return limited-scope token if 2FA is on
    const dataInToken = {
        _id: user._id,
        email: user.email,
        multiFactorEnabled: user.multiFactorEnabled,
        isSecondFactorAuthed: false
    };

    //create and assign a token that is valid for 1 hour
    const token = jwt.sign(
        { dataInToken },
        user.password,
        { expiresIn: '1h' }
    );

    //send the token to the client
    return res.status(201).header('auth-token', token).json({
        message: '2FA is enabled',
        token: token
    });
}
);

router.post('/reset-password', async (req, res) => {
    //get the data from the request
    //use sendgrid to send email
    const { email } = req.body;

    try {
        //check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'User does not exist'
            });
        }
        //if a user has already requested a reset token, delete the previous one
        const previousToken = await Reset.findOne({ email });
        if (previousToken) {
            await previousToken.remove();
        }
        //generate a temporary token for the user and store it in a separate collection called 'reset-tokens' 
        const token = await passwordUtil.generateToken();
        console.log(token);
        const resetToken = new Reset({
            email: user.email,
            resetToken: token,
            expiresAt: Date.now() + 3600000
        });
        await resetToken.save();
        //send the token to the user's email

        const url = `http://localhost:3000/reset-password/${token}`;
        const subject = 'Reset Password';
        const text = `Please click the following link to reset your password: ${url}`;
        const html = `<p>Someone (hopefully you) has requested a password reset.\n\n
        Please click the following link to reset your password:\n <a href="${url}">${url}</a></p>`;
        const data = {
            from: '',
            to: user.email,
            subject: subject,
            text: text,
            html: html
        };
        sgMail.send(data);
        res.status(200).json({
            message: 'Email sent'
        });

    }
    catch (err) {
        res.status(400).json({
            message: err.message
        });
    }
});

router.post('/reset-password/:token', async (req, res) => {
    //get the data from the request
    const { email, password } = req.body;
    const token = req.params.token;

    //check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({
            message: 'User does not exist'
        });
    }
    //check if the token is valid
    const resetToken = await Reset.findOne({ email, token });
    if (!resetToken) {
        return res.status(400).json({
            message: 'Invalid token'
        });
    }
    //hash the password and update the user
    const hashedPassword = await passwordUtil.generatePassword(password);
    user.password = hashedPassword;
    await user.save();
    //delete the token from the database
    await resetToken.remove();
    //send the token to the client
    return res.status(200).json({
        message: 'Password reset successful'
    });
}
);



router.post('/2fa/:state', async (req, res) => {
    //get the jwt token from the request and decode it

    if (!req.params.state) {
        return res.status(400).json({
            message: 'Please enable or disable 2FA.'
        });
    }

    const state = req.params.state;

    if (state === 'enable') {
        const token = req.headers['auth-token'];
        try {
            let payload = utils.parseJwt(token)
            const user = await User.findOne(
                { _id: payload.dataInToken._id }
            );
            const decoded = jwt.verify(
                token,
                user.password
            );

            if (!user) {
                return res.status(400).json({
                    message: 'User does not exist'
                });
            }

            //check if user already enabled 2fa
            if (user.multiFactorEnabled) {
                return res.status(400).json({
                    message: '2FA is already enabled'
                });
            }

            if (!decoded) {
                return res.status(400).json({
                    message: 'Invalid token'
                });
            }

            const secret = speakeasy.generateSecret({
                name: `Spencer 2FA (${user.email})`
            });



            //store the encrypted secret key in the database
            user.secretKey = secret.base32;
            // user.multiFactorEnabled = true;
            await user.save();

            qrcode.toDataURL(
                secret.otpauth_url,
                function (err, qrImage) {
                    if (err) {
                        return res.status(400).json({
                            message: 'Error generating QR code'
                        });
                    }
                    //set header with new jwt token
                    const dataInToken = {
                        _id: user._id,
                        email: user.email,
                        multiFactorEnabled: user.multiFactorEnabled,
                        isSecondFactorAuthed: true
                    }
                    const token = jwt.sign(
                        { dataInToken },
                        user.password,
                        { expiresIn: '1h' }
                    );
                    return res.header('auth-token', token).send(
                        `<img src="${qrImage}" alt="QR Code" />`,
                    );
                    //return res.status(200).send(`<img src="${qrImage}" alt="QR Code" />`);
                    // return res.status(200).json({
                    //     message: 'QR code generated',
                    //     qrImage: qrImage,
                    //     secret: secret
                    // });
                });


        }
        catch (err) {
            console.log(err)
            return res.status(400).json({
                message: 'Invalid token',
                error: err
            });
        }
    }
    else if (state === 'disable') {
        const token = req.headers['auth-token'];

        try {

            let payload = utils.parseJwt(token)
            const user = await User.findOne(
                { _id: payload.dataInToken._id }
            );
            const decoded = jwt.verify(
                token,
                user.password
            );

            //find the user by the id in the decoded token.
            //const user = await User.findOne({ _id: decoded.dataInToken._id });
            if (!user) {
                return res.status(400).json({
                    message: 'User does not exist'
                });
            }

            //check if the token is valid
            if (!decoded) {
                return res.status(400).json({
                    message: 'Invalid token 1'
                });
            }
            if (decoded) {
                user.multiFactorEnabled = false;
                user.secretKey = '';
                await user.save();
                return res.status(200).json({
                    message: '2FA disabled'
                });
            } else {
                return res.status(400).json({
                    message: 'Invalid token 2'
                });
            }

        }
        catch (err) {
            console.log(err)
            return res.status(400).json({
                message: 'Invalid token', error: err
            });
        }
    }

})

router.post('/2fa', async (req, res) => {
    //get the data from the request
    if (!req.body.otp) {
        return res.status(400).json({
            message: "OTP is required"
        })
    }
    const { otp } = req.body;
    const token = req.headers['auth-token'];

    //get the user in the database
    const user = await User.findOne({ _id: req.user._id });
    if (!user) {
        return res.status(400).json({
            message: 'User does not exist'
        });
    }

    try {
        //check if a secretKey exists
        if (!user.secretKey && !user.multiFactorEnabled) {
            return res.status(400).json({
                message: '2FA is not enabled'
            });
        }

        const decoded = jwt.verify(
            token,
            req.privateKey
        );

        if (!decoded) {
            return res.status(400).json({
                message: 'Invalid token'
            });
        }

        // if this is the first time the user is authenticating with 2FA, 
        // fully enable 2FA by setting user.multiFactorEnabled to true
        if (!user.multiFactorEnabled && user.secretKey) {
            await utils.verifyOTP(otp, req, res);
            user.multiFactorEnabled = true;
            await user.save();
            return;
        }

        await utils.verifyOTP(otp, req, res);
    }
    catch (err) {
        console.log(err)
        return res.status(400).json({
            message: 'Invalid token',
            err: err
        });
    }
})


module.exports = router;