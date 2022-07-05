const bcrypt = require('bcryptjs');

let generatePassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
}

let comparePasswords = async (password, hashedPassword) => {
    const isMatch = await bcrypt.compare(password, hashedPassword);
    return isMatch;
}

let generateToken = async () => {
    //generate a random string of characters and numbers that is 64 characters long
    const token = await bcrypt.genSalt(64);
    console.log(token)
    return token;
}

module.exports = { generatePassword, comparePasswords, generateToken };