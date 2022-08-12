const path = require('path');
const grpc = require('@grpc/grpc-js');
let config = require('./database/index');
const protoLoader = require('@grpc/proto-loader');
const { RegisterHandler, LoginHandler, GetMeHandler, LogoutHandler } = require('./handler/index');
let mysql = require('mysql');
let connection = mysql.createConnection(config);

const options = {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
};

const PORT = 8181;
const PROTO_FILE = '../proto/services.proto';
const packageDef = protoLoader.loadSync(
    path.resolve(__dirname, PROTO_FILE),
    options
);

const proto = grpc.loadPackageDefinition(packageDef);

const authPackage = proto.auth;

const server = new grpc.Server();
server.addService(authPackage.AuthService.service, {
    SignUpUser: (req, res) => RegisterHandler(req, res),
    SignInUser: (req, res) => LoginHandler(req, res)
});

server.bindAsync(
    `0.0.0.0:${PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (err, port) => {
        if (err) {
            console.error(err);
            return;
        }
        server.start();
        console.log(`Server listening on port: ${port}`);
        try {
            connection.connect(function (err) {
                if (err) {
                    return console.error('error: ' + err.message);
                }
                console.log('Connected to the Database.');
            });
        } catch (error) {
            console.log(error)
        }
    }
);
