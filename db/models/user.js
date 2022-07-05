const db = require("../db");

const userSchema = new db.Schema({
    username: String,
    password: String,
    email: String,
    multiFactorEnabled: Boolean,
    secretKey: String
    
 });


const User = db.model("Users", userSchema);

module.exports = User;