const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("node:crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "> ",
});

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

let registeredUsername = "";
let username = "";
let targetUsername = "";
const users = new Map();

socket.on("connect", () => {
    console.log("Connected to the server");

    rl.question("Enter your username: ", (input) => {
        username = input;
        registeredUsername = input;
        console.log(`Welcome, ${username} to the chat`);

        socket.emit("registerPublicKey", {
            username,
            publicKey,
        });
        rl.prompt();

        rl.on("line", (message) => {
            if (message.trim()) {
                let match;
                if ((match = message.match(/^!secret (\w+)$/))) {
                    targetUsername = match[1];
                    console.log(`Now secretly chatting with ${targetUsername}`);
                } else if (message.match(/^!exit$/)) {
                    console.log(`No more secretly chatting with ${targetUsername}`);
                    targetUsername = "";
                } else {
                    if (targetUsername) {
                        const targetPublicKey = users.get(targetUsername);
                        if (targetPublicKey) {
                            const encryptedMessage = crypto
                                .publicEncrypt(
                                    {
                                        key: targetPublicKey,
                                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                                        oaepHash: "sha256",
                                    },
                                    Buffer.from(message, "utf8")
                                )
                                .toString("base64");

                            socket.emit("message", {
                                username,
                                message: encryptedMessage,
                                isSecret: true,
                                target: targetUsername,
                            });
                        } else {
                            console.log(`User ${targetUsername} not found or has no public key.`);
                        }
                    } else {
                        socket.emit("message", { username, message, isSecret: false });
                    }
                }
            }
            rl.prompt();
        });
    });
});

socket.on("init", (keys) => {
    keys.forEach(([user, key]) => users.set(user, key));
    console.log(`\nThere are currently ${users.size} users in the chat`);
    rl.prompt();
});

socket.on("newUser", (data) => {
    const { username: newUser, publicKey: newKey } = data;
    users.set(newUser, newKey);
    console.log(`${newUser} join the chat`);
    rl.prompt();
});

socket.on("message", (data) => {
    const { username: senderUsername, message: senderMessage, isSecret } = data;
    if (senderUsername !== registeredUsername) {
        if (isSecret) {
            try {
                const decryptedMessage = crypto
                    .privateDecrypt(
                        {
                            key: privateKey,
                            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                            oaepHash: "sha256",
                        },
                        Buffer.from(senderMessage, "base64")
                    )
                    .toString("utf8");

                console.log(`${senderUsername} (secret): ${decryptedMessage}`);
            } catch (err) {
                console.log(`${senderUsername}: ${senderMessage}`);
            }
        } else {
            console.log(`${senderUsername}: ${senderMessage}`);
        }
        rl.prompt();
    }
});

socket.on("disconnect", () => {
    console.log("Server disconnected, Exiting...");
    rl.close();
    process.exit(0);
});

rl.on("SIGINT", () => {
    console.log("\nExiting...");
    socket.disconnect();
    rl.close();
    process.exit(0);
});