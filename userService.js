var mongoose = require('mongoose');
var Schema = mongoose.Schema;

const env = require('dotenv');
const bcrypt = require('bcryptjs');
env.config()

var userSchema = new Schema({
    userName: {  
        type: String,
        unique: true
    },
    password: String,
    email: String,
    loginHistory: [{
        dateTime: Date,
        userAgent: String
    }]
});


let User;

module.exports.initialize = function () {
    return new Promise((resolve, reject) => {
        let db = mongoose.createConnection(process.env.MONGO_URI_STRING);

        db.on('error', (err) => {
            reject(err); 
        });
        db.once('open', () => {
            console.log("MONGO DATABASE CONNECTED!")
            User = db.model("users", userSchema);
            resolve();
        });
    });
};

module.exports.registerUser = function (userData) {
    return new Promise((resolve, reject) => {
        // Check if the userName is missing or null
        if (!userData.userName || userData.userName.trim() === "") {
            return reject("USERNAME CANNOT BE EMPTY");
        }

        // Convert the userName to lowercase to ensure consistency
        userData.userName = userData.userName.toLowerCase();
        console.log("Processed Username:", userData.userName); // Confirm it's correct

        if (userData.password != userData.password2) {
            reject("PASSWORDS DO NOT MATCH!");
        } else {
            User.findOne({ userName: userData.userName }).then((existingUser) => {
                if (existingUser) {
                    reject("USERNAME IS TAKEN");
                } else {
                    bcrypt.hash(userData.password, 10).then((hash) => {
                        userData.password = hash;
                        let newUser = new User(userData);
                        newUser.save().then(() => {
                            resolve();
                        }).catch((err) => {
                            reject(err);
                        });
                    }).catch((err) => {
                        console.log(err);
                        reject("ERROR WITH PASSWORD ENCRYPTION");
                    });
                }
            }).catch((err) => {
                reject("ERROR CHECKING USERNAME AVAILABILITY");
            });
        }
    });
};

module.exports.loginUser = function (userData) {
    return new Promise((resolve, reject) => {
        // Convert the username to lowercase before checking
        userData.userName = userData.userName.toLowerCase();

        User.findOne({ userName: userData.userName })
            .exec()
            .then((user) => {
                if (!user) {
                    reject("UNABLE TO FIND USER: " + userData.userName);
                } else {
                    bcrypt.compare(userData.password, user.password).then((result) => {
                        if (result === true) {
                            user.loginHistory.push({ dateTime: new Date(), userAgent: userData.userAgent });
                            User.updateOne({ userName: user.userName }, {
                                $set: { loginHistory: user.loginHistory }
                            }).exec()
                                .then(() => {
                                    resolve(user);
                                }).catch((err) => {
                                    reject("ERROR UPDATING LOGIN HISTORY");
                                });
                        } else {
                            reject("UNABLE TO AUTHENTICATE USER: " + userData.userName);
                        }
                    }).catch((err) => {
                        reject("DECRYPTION ERROR");
                    });
                }
            }).catch((err) => {
                reject("UNABLE TO FIND USER: " + userData.userName);
            });
    });
};


