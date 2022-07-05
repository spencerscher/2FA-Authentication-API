const db = require("../db");

const resetSchema = new db.Schema({
    email: String,
    //reset token with TTL of 30 seconds
    resetToken: String,
    expiresAt: { type: Date, expires: '1h', default: Date.now }
 });


const Reset = db.model("Resets", resetSchema);

module.exports = Reset;