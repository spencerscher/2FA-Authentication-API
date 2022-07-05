// to use mongoDB
const mongoose = require("mongoose");
mongoose.connect('', { useNewUrlParser: true, useUnifiedTopology: true }, (err) => {
    if (err) {
        console.log(err);
    }
    else {
        console.log("Connected to database.");
    }
});

module.exports = mongoose;