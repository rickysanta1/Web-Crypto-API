// Derivar la clave desde la contraseña usando PBKDF2
async function deriveKey(text, algo,salt=false) {
      // Generar salt aleatorio (8/16 bytes)
    // salt = salt?salt:new TextEncoder("utf-8").encode("salto");
    salt = salt?salt:crypto.getRandomValues(new Uint8Array(8));
// Convertir todo a hexadecimal
    const bufferToHex = buffer => Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    
        const keyMaterial = await crypto.subtle.importKey("raw",new TextEncoder().encode(text),{ name: "PBKDF2" },false,["deriveKey"]);

    const key = await crypto.subtle.deriveKey({name: "PBKDF2", salt: salt,iterations: 100000,hash: "SHA-256"},keyMaterial,{ name: algo, length: 256 },false,["encrypt", "decrypt"]);

    return {key,salt};
}

async function encryptText(text, password) {
    // Codificar el texto a cifrar
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
console.log("Encriptando!")

    const {key,salt} = await deriveKey(password, "AES-GCM");

    // Generar IV aleatorio (12 bytes para AES-GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Cifrar el texto
    const encryptedData = await crypto.subtle.encrypt({name: "AES-GCM",iv},key,data);

    // Convertir todo a hexadecimal
    const bufferToHex = buffer => Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    // Combinar salt + iv + datos cifrados en hexadecimal
    return bufferToHex(salt) + bufferToHex(iv) + bufferToHex(encryptedData);
}

// Función de desencriptación
async function decryptText(encryptedHex, password) {
    // Decodificar hexadecimal
    const hexToBuffer = hex => new Uint8Array(hex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));

    // Extraer componentes (salt: 16 chars, iv: 24 chars, resto: ciphertext)
    const salt = hexToBuffer(encryptedHex.slice(0, 16));
    const iv = hexToBuffer(encryptedHex.slice(16, 40));
    const ciphertext = hexToBuffer(encryptedHex.slice(40));

    const {key} = await deriveKey(password, "AES-GCM",salt);

    // Desencriptar
    const decryptedData = await crypto.subtle.decrypt({name: "AES-GCM",iv},key,ciphertext);

    return new TextDecoder().decode(decryptedData);
}

// Ejemplo de uso
// (async () => {
//     const password = "MiContrasenaSecreta!";
//     const textoOriginal = "couch hire reopen joy catch duck crouch citizen expose merit rib ring";
//     console.log("textoOriginal:", textoOriginal);
//     try {
//         const encrypted = await encryptText(textoOriginal, password);
//         console.log("Encriptado:", encrypted);
        
//         const decrypted = await decryptText(encrypted, password);
//         console.log("Desencriptado:", decrypted);
//     } catch (error) {
//         console.error("Error:", error);
//     }
// })();
