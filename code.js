document.addEventListener('DOMContentLoaded', () => {
    const dataInput = document.getElementById('data-input');
    const dataOutput = document.getElementById('data-output');
    const decryptButton = document.getElementById('decrypt');
    const encryptButton = document.getElementById('encrypt');
    const secret = document.getElementById('secret');
    const initializationVector = document.getElementById('iv');
    const message = document.getElementById('message');

    const getStringFromArrayBuffer = (buffer) => btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
    const getArrayBufferFromString = (string) => new Uint8Array(atob(string).split('').map((c) => c.charCodeAt(0)));

    const encryptText = async (plainText, password) => {
        const ptUtf8 = new TextEncoder().encode(plainText);
        const pwUtf8 = new TextEncoder().encode(password);
        const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const alg = { name: 'AES-GCM', iv: iv };
        const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']);

        return { iv, encBuffer: await crypto.subtle.encrypt(alg, key, ptUtf8) };
    };

    const decodeBufferWithWhitespace = (buffer) => {
        let decodedString = new TextDecoder().decode(buffer);
        decodedString = decodedString.replace(/\u0000/g, ' ');
        return decodedString;
    };

    const decryptText = async (ctBuffer, iv, password) => {
        const pwUtf8 = new TextEncoder().encode(password);
        const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);

        const alg = { name: 'AES-GCM', iv: iv };
        const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']);

        const ptBuffer = await crypto.subtle.decrypt(alg, key, ctBuffer);
        const plaintext = decodeBufferWithWhitespace(ptBuffer);

        return plaintext;
    };

    decryptButton.addEventListener('click', async () => {
        if (!secret.value) {
            dataOutput.innerHTML = '';
            message.innerText = 'No secret , unable to encrypt.';
            return;
        }
        let text = await decryptText(
            getArrayBufferFromString(dataInput.value),
            getArrayBufferFromString(initializationVector.value),
            secret.value
        );
        
        dataOutput.innerHTML = `<div style="white-space: pre-wrap;">${text}</div>`;
    });

    encryptButton.addEventListener('click', async () => {
        if (!secret.value) {
            dataOutput.innerHTML = '';
            message.innerText = 'No secret , unable to encrypt.';
            return;
        }
        let { iv, encBuffer } = await encryptText(dataInput.value, secret.value);
        
        dataOutput.innerHTML = `
            <code>${getStringFromArrayBuffer(encBuffer)}</code>
            <h4>iv:</h4>
            <pre>${getStringFromArrayBuffer(iv)}</pre>`;
    });
	document.getElementById("show-password").addEventListener("change", function() {
		var secretInput = document.getElementById("secret");
		if (this.checked) {
			secretInput.type = "text";
		} else {
			secretInput.type = "password";
		}
	});
	
});