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

function hashMessage(msg) {
    return crypto.createHash("sha256").update(msg).digest("hex");
}

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
                if ((match = message.match(/^!impersonate (\w+)$/))) {
                    username = match[1];
                    console.log(`Now impersonating as ${username}`);
                } else if ((match = message.match(/^!secret (\w+)$/))) {
                    targetUsername = match[1];
                    console.log(`Now secretly chatting with ${targetUsername}`);
                } else if (message.match(/^!exit$/)) {
                    username = registeredUsername;
                    targetUsername = "";
                    console.log(`Back to normal mode as ${username}`);
                } else {
                    let payloadMessage = message;
                    let isSecret = false;

                    if (targetUsername) {
                        const targetPublicKey = users.get(targetUsername);
                        if (targetPublicKey) {
                            payloadMessage = crypto
                                .publicEncrypt(
                                    {
                                        key: targetPublicKey,
                                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                                        oaepHash: "sha256",
                                    },
                                    Buffer.from(message, "utf8")
                                )
                                .toString("base64");
                            isSecret = true;
                        } else {
                            console.log(`User ${targetUsername} not found.`);
                            rl.prompt();
                            return;
                        }
                    }

                    const hash = hashMessage(payloadMessage);
                    const signature = crypto
                        .sign("sha256", Buffer.from(payloadMessage, "utf8"), privateKey)
                        .toString("hex");

                    socket.emit("message", {
                        username,
                        message: payloadMessage,
                        hash,
                        signature,
                        isSecret,
                    });
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
    const { username: senderUsername, message: senderMessage, hash, signature, isSecret } = data;

    if (senderUsername !== registeredUsername) {
        // 1. Cek Integrity (Hash)
        if (hash && hashMessage(senderMessage) !== hash) {
            console.log(`\n[WARNING] Message from ${senderUsername} may have been modified!`);
        }

        // 2. Cek Authenticity (RSA Signature)
        const senderPublicKey = users.get(senderUsername);
        let isValid = false;
        if (senderPublicKey && signature) {
            try {
                isValid = crypto.verify(
                    "sha256",
                    Buffer.from(senderMessage, "utf8"),
                    senderPublicKey,
                    Buffer.from(signature, "hex")
                );
            } catch (err) {
                isValid = false;
            }
        }

        if (!isValid) {
            console.log(`\n[WARNING] This user is fake! (${senderUsername})`);
        }

        // 3. Cek Confidentiality (Decrypt jika Secret Chat)
        if (isSecret) {
            try {
                const decrypted = crypto
                    .privateDecrypt(
                        {
                            key: privateKey,
                            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                            oaepHash: "sha256",
                        },
                        Buffer.from(senderMessage, "base64")
                    )
                    .toString("utf8");
                console.log(`${senderUsername} (secret): ${decrypted}`);
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