// --- BASIC FUNCTIONS ---
const LOCAL_STORAGE_KEY = 'credentialList';
const DEFAULT_TIMEOUT = 60000;
const SERVER_CHALLENGE = Uint8Array.from("abcd", c => c.charCodeAt(0));
const PUBLIC_KEY_CREDENTIAL_PARAMETERS = [
    { alg: -7, type: "public-key" },
    { alg: -8, type: "public-key" },
    { alg: -35, type: "public-key" },
    { alg: -36, type: "public-key" },
    { alg: -37, type: "public-key" },
    { alg: -38, type: "public-key" },
    { alg: -39, type: "public-key" },
    { alg: -257, type: "public-key" },
    { alg: -258, type: "public-key" },
    { alg: -259, type: "public-key" },
];
const getRelyingParty = () => {
    return {
        name: document.querySelector("#input-relying-party").value,
        id: (window.location.host).includes('localhost') ? 'localhost' : window.location.host,
        // id: 'surge.sh'
    };
};
const getUser = () => {
    return {
        name: document.querySelector("#input-user-name").value,
        displayName: document.querySelector("#input-user-name").value,
        id: Uint8Array.from(document.querySelector("#input-user-id").value, c => c.charCodeAt(0))
    };
}
const getPublicKeyCredentialCreationOptions = () => {
    return {
        challenge: SERVER_CHALLENGE,
        rp: getRelyingParty(),
        user: getUser(),
        pubKeyCredParams: PUBLIC_KEY_CREDENTIAL_PARAMETERS,
        authenticatorSelection: {
            // "authenticatorAttachment": "platform",
            // "residentKey": "preferred",
            // "requireResidentKey": false,
            // "userVerification": "preferred",
        },
        timeout: DEFAULT_TIMEOUT,
        attestation: document.querySelector("#input-attestation-preference").value
    };
};
const getPublicKeyCredentialRequestOptions = (credentialIDs) => {
    return {
        challenge: SERVER_CHALLENGE,
        allowCredentials: credentialIDs.map(credentialID => {
            return {
                id: Uint8Array.from(atob(credentialID), c => c.charCodeAt(0)),
                type: 'public-key',
                transports: ['ble', 'internal', 'hybrid'],
            }
        }),
        timeout: DEFAULT_TIMEOUT
    };
};
const addToLocalStorage = (credentialIDString) => {
    const correctCredentialIDString = credentialIDString.replace(/-/g, '+').replace(/_/g, '/');;
    const credentialList = JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEY)) || [];
    if (!credentialList.includes(correctCredentialIDString)) credentialList.push(correctCredentialIDString);
    localStorage.setItem('credentialList', JSON.stringify(credentialList));
}
const getFromLocalStorage = () => {
    return JSON.parse(localStorage.getItem(LOCAL_STORAGE_KEY)) || [];
};
// --- ---


// --- PARSING FUNCTIONS ---
const parseAuthenticatorData = function (decodedAttestationObject) {
    const { authData } = decodedAttestationObject;

    // get the length of the credential ID
    const dataView = new DataView(new ArrayBuffer(2));
    const idLenBytes = authData.slice(53, 55);
    idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
    const credentialIdLength = dataView.getUint16();

    // get the credential ID
    // const credentialId = authData.slice(55, 55 + credentialIdLength);
    // console.log(credentialId);
    // const credentialIdString = new TextDecoder().decode(credentialId);
    // console.log(`credentialIdString:`);
    // console.log(credentialIdString);

    // get the public key object
    const publicKeyBytes = authData.slice(55 + credentialIdLength);

    // the publicKeyBytes are encoded again as CBOR
    const publicKeyObject = CBOR.decode(publicKeyBytes.buffer);
    console.log(`publicKeyObject:`);
    console.log(publicKeyObject)
};

const parseCredential = function (credential) {
    console.log(`CREDENTIAL:`);
    console.log(credential);
    console.log(`getClientExtensionResults:`);
    console.log(credential.getClientExtensionResults());

    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(credential.response.clientDataJSON);
    const clientDataObj = JSON.parse(decodedClientData);
    console.log(`clientDataJSON:`);
    console.log(clientDataObj);


    const decodedAttestationObj = CBOR.decode(credential.response.attestationObject);
    console.log(`attestationObject:`);
    console.log(decodedAttestationObj);
    return decodedAttestationObj;
};

const parseAssertion = function (assertion) {
    console.log(`ASSERTION:`);
    console.log(assertion);

    console.log(`getClientExtensionResults:`);
    console.log(assertion.getClientExtensionResults());

    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(assertion.response.clientDataJSON);
    const clientDataObj = JSON.parse(decodedClientData);
    console.log(`clientDataJSON:`);
    console.log(clientDataObj);
};
// --- ---



// --- WEBAUTHN FUNCTIONS ---
const getCredential = async (publicKeyCredentialCreationOptions) => {
    return await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
    });
};

const getAssertion = async (publicKeyCredentialRequestOptions) => {
    return await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
    });
};
// --- ---



// --- CONTROLLER FUNCTIONS ---
const registration = async () => {
    console.log(`--- Registration Start ---`);
    const publicKeyCredentialCreationOptions = getPublicKeyCredentialCreationOptions();
    console.log(`OPTIONS:`);
    console.log(publicKeyCredentialCreationOptions);

    const credential = await getCredential(publicKeyCredentialCreationOptions);
    const decodedAttestationObj = parseCredential(credential);
    parseAuthenticatorData(decodedAttestationObj);
    console.log(`--- Registration End ---`);

    document.getElementById("textid").innerHTML = JSON.stringify(decodedAttestationObj);
    addToLocalStorage(credential.id);
}

const authentication = async () => {
    console.log(`--- Authentication Start ---`);
    const credentialIDs = getFromLocalStorage();
    const publicKeyCredentialRequestOptions = getPublicKeyCredentialRequestOptions(credentialIDs);
    console.log(`OPTIONS:`);
    console.log(publicKeyCredentialRequestOptions);

    const assertion = await getAssertion(publicKeyCredentialRequestOptions);
    parseAssertion(assertion);
    console.log(`--- Authentication End ---`);
}
// --- ---