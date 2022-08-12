const bcrypt = require('bcrypt');
const { signJwt } = require('../utils/jwt');
const grpc = require('@grpc/grpc-js');
const jwt = require('jsonwebtoken');
let mysql = require('mysql');
let config = require('../database/index');
let connection = mysql.createConnection(config);

const RegisterHandler = async (req, res) => {
    let { name, email, password } = req.request;
    // Check if email, phone or password is empty
    if (!email || !name || !password) res({ code: grpc.status.INVALID_ARGUMENT, message: 'Email, phone or password is required!', });
    else {
        try {
            // Check if email already exists
            connection.query(`SELECT id from users WHERE email="${email}"`, async function (err, result) {
                if (err) res({ code: grpc.status.INTERNAL, message: 'Server Error', });
                else if (result.length) res({ code: grpc.status.ALREADY_EXISTS, message: 'Email already exists', });

                if (!err && result.length === 0) {
                    // Generate hashed password
                    password = await bcrypt.hash(password, 12);

                    // Create User into Database
                    connection.query("INSERT into users values(?,?,?,?)", [null, name, email, password], (error, response) => {
                        if (error) res({ code: grpc.status.INTERNAL, message: 'Can not register user', });
                        console.log(response)
                        res(null, {
                            user: {
                                id: response.insertId,
                                name,
                                email,
                            }
                        });
                    });
                }
            });
        } catch (err) {
            res({ code: grpc.status.INTERNAL, message: err.message });
        }
    }
};

const LoginHandler = async (req, res) => {
    const { email, password } = req.request;
    try {
        //find a user using email
        connection.query(`SELECT * from users WHERE email="${email}"`, async function (err, result) {
            if (err) res({ code: grpc.status.INTERNAL, message: 'Server Error', });
            if (result.length === 0) res({ code: grpc.status.NOT_FOUND, message: 'Invalid Credentials!', });

            if (!err && result.length !== 0) {
                const user = { ...result[0] };

                // Check if user exist and password is correct
                if (!(await bcrypt.compare(password, user.password))) {
                    res({ code: grpc.status.INVALID_ARGUMENT, message: 'Invalid email or password!', });
                }
                else {
                    // Create token
                    const token = signJwt(user);

                    res(null, {
                        status: 'success',
                        token,
                    });
                }
            }
        });
    } catch (err) {
        res({ code: grpc.status.INTERNAL, message: err.message });
    }
};


module.exports = {
    RegisterHandler: RegisterHandler,
    LoginHandler: LoginHandler,
};

