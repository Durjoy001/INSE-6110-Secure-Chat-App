// Generate RSA key pairs for encryption and signing
const generateKeyPair = async () => {
    // Generate encryption key pair
    const encryptionKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    // Generate signing key pair
    const signingKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
    );

    // Export encryption keys
    const encryptionPublicKey = await window.crypto.subtle.exportKey(
        "spki",
        encryptionKeyPair.publicKey
    );
    const encryptionPrivateKey = await window.crypto.subtle.exportKey(
        "pkcs8",
        encryptionKeyPair.privateKey
    );

    // Export signing keys
    const signingPublicKey = await window.crypto.subtle.exportKey(
        "spki",
        signingKeyPair.publicKey
    );
    const signingPrivateKey = await window.crypto.subtle.exportKey(
        "pkcs8",
        signingKeyPair.privateKey
    );

    // Convert to base64 strings
    const encryptionPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptionPublicKey)));
    const encryptionPrivateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptionPrivateKey)));
    const signingPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(signingPublicKey)));
    const signingPrivateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(signingPrivateKey)));

    return {
        encryptionPublicKey: encryptionPublicKeyBase64,
        encryptionPrivateKey: encryptionPrivateKeyBase64,
        signingPublicKey: signingPublicKeyBase64,
        signingPrivateKey: signingPrivateKeyBase64
    };
};

// Encrypt message with public key
const encryptMessage = async (message, publicKeyBase64) => {
    try {
        console.log("Message to encrypt:", message);

        // Validate inputs
        if (!message || !publicKeyBase64) {
            throw new Error("Missing message or public key");
        }

        // Convert base64 to ArrayBuffer
        let publicKeyBuffer;
        try {
            publicKeyBuffer = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));
        } catch (error) {
            console.error("Error converting public key from base64:", error);
            throw new Error("Invalid public key format");
        }
        
        // Import public key
        let publicKey;
        try {
            publicKey = await window.crypto.subtle.importKey(
                "spki",
                publicKeyBuffer,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                true,
                ["encrypt"]
            );
        } catch (error) {
            console.error("Error importing public key:", error);
            throw new Error("Failed to import public key");
        }

        // Convert message to buffer
        const messageBuffer = new TextEncoder().encode(message);
        
        // Encrypt message
        let encryptedBuffer;
        try {
            encryptedBuffer = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                publicKey,
                messageBuffer
            );
            console.log("Message encrypted successfully");
        } catch (error) {
            console.error("Error during encryption:", error);
            throw new Error("Failed to encrypt message");
        }

        // Convert to base64
        const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
        
        return encryptedBase64;
    } catch (error) {
        console.error("Error in encryptMessage:", error);
        throw error;
    }
};

// Decrypt message with private key
const decryptMessage = async (encryptedMessageBase64, privateKeyBase64) => {
    try {
        console.log("Starting message decryption");

        // Validate inputs
        if (!encryptedMessageBase64 || !privateKeyBase64) {
            throw new Error("Missing encrypted message or private key");
        }

        // Convert base64 to ArrayBuffer
        let privateKeyBuffer;
        let encryptedBuffer;
        try {
            privateKeyBuffer = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
            encryptedBuffer = Uint8Array.from(atob(encryptedMessageBase64), c => c.charCodeAt(0));
        } catch (error) {
            console.error("Error converting base64 to buffer:", error);
            throw new Error("Invalid base64 format for message or key");
        }
        
        // Import private key
        let privateKey;
        try {
            privateKey = await window.crypto.subtle.importKey(
                "pkcs8",
                privateKeyBuffer,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                true,
                ["decrypt"]
            );
        } catch (error) {
            console.error("Error importing private key:", error);
            throw new Error("Failed to import private key");
        }

        // Decrypt message
        let decryptedBuffer;
        try {
            decryptedBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                privateKey,
                encryptedBuffer
            );
            console.log("Message decrypted successfully");
        } catch (error) {
            console.error("Error during decryption:", error);
            console.error("Error details:", {
                messageLength: encryptedMessageBase64.length,
                keyLength: privateKeyBase64.length,
                bufferLength: encryptedBuffer.length,
                errorName: error.name,
                errorMessage: error.message
            });
            throw new Error("Failed to decrypt message");
        }

        // Convert to string
        const decryptedMessage = new TextDecoder().decode(decryptedBuffer);
        console.log("Decrypted message:", decryptedMessage);
        
        return decryptedMessage;
    } catch (error) {
        console.error("Error in decryptMessage:", error);
        throw error;
    }
};

// Generate digital certificate
const generateCertificate = (publicKeys, username) => {
    console.log("Generating certificate for username:", username);
    
    if (!username) {
        throw new Error("Username is required for certificate generation");
    }
    
    if (!publicKeys || !publicKeys.encryptionPublicKey || !publicKeys.signingPublicKey) {
        throw new Error("Both encryption and signing public keys are required");
    }
    
    const cert = {
        subject: username,
        publicKeys: {
            encryptionPublicKey: publicKeys.encryptionPublicKey,
            signingPublicKey: publicKeys.signingPublicKey
        },
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year validity
    };
    
    console.log("Generated certificate:", JSON.stringify(cert, null, 2));
    return cert;
};

// Update signMessage to use signing private key
const signMessage = async (message, signingPrivateKeyBase64) => {
    try {
        // Validate inputs
        if (!message || !signingPrivateKeyBase64) {
            throw new Error("Missing message or signing private key");
        }

        // Convert base64 to ArrayBuffer
        const signingPrivateKeyBuffer = Uint8Array.from(atob(signingPrivateKeyBase64), c => c.charCodeAt(0));
        
        // Import signing private key
        const signingPrivateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            signingPrivateKeyBuffer,
            {
                name: "RSA-PSS",
                hash: "SHA-256",
            },
            true,
            ["sign"]
        );

        // Convert message to buffer
        const messageBuffer = new TextEncoder().encode(message);
        
        // Generate signature
        const signature = await window.crypto.subtle.sign(
            {
                name: "RSA-PSS",
                saltLength: 32,
            },
            signingPrivateKey,
            messageBuffer
        );

        // Convert signature to base64
        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
        
        return signatureBase64;
    } catch (error) {
        console.error("Error in signMessage:", error);
        throw error;
    }
};

// Update verifySignature to use signing public key
const verifySignature = async (message, signatureBase64, signingPublicKeyBase64) => {
    try {
        // Validate inputs
        if (!message || !signatureBase64 || !signingPublicKeyBase64) {
            throw new Error("Missing message, signature, or signing public key");
        }

        console.log("Verifying signature for message:", message);

        // Convert base64 to ArrayBuffer
        const signingPublicKeyBuffer = Uint8Array.from(atob(signingPublicKeyBase64), c => c.charCodeAt(0));
        const signatureBuffer = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

        console.log("Importing signing public key");
        // Import signing public key
        const signingPublicKey = await window.crypto.subtle.importKey(
            "spki",
            signingPublicKeyBuffer,
            {
                name: "RSA-PSS",
                hash: "SHA-256",
            },
            true,
            ["verify"]
        );

        // Convert message to buffer
        const messageBuffer = new TextEncoder().encode(message);

        console.log("Verifying signature");
        // Verify signature
        const isValid = await window.crypto.subtle.verify(
            {
                name: "RSA-PSS",
                saltLength: 32,
            },
            signingPublicKey,
            signatureBuffer,
            messageBuffer
        );

        console.log("Signature verified:", isValid);
        return isValid;
    } catch (error) {
        console.error("Error in verifySignature:", error);
        throw error;
    }
};

export {
    generateKeyPair,
    encryptMessage,
    decryptMessage,
    generateCertificate,
    signMessage,
    verifySignature
}; 