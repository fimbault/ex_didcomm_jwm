/*
    Alice prepares JWM = JWE(JWS(payload)) to send to Bob 
    To be later encapsulated into a transport https://github.com/decentralized-identity/didcomm-messaging
*/

const jose = require('jose');
const base64url = require('base64url');
const fs = require('fs-extra');

async function main() {
    //Payload definition
    const payload = {
        id: "urn:uuid:ef5a7369-f0b9-4143-a49d-2b9c7ee51117",
        type: "didcomm",
        from: "did:example:alice",
        expiry: 1516239022,
        time_stamp: 1516269022,
        body: { message: "Challenge!" }
    };

    //Get sender key
    const senderJWK = JSON.parse(await fs.readFile("example-keys/alice.json"));
    const jwsKey = jose.JWK.asKey(senderJWK);

    //Sign
    const jws = new jose.JWS.Sign(payload);

    //Hmm, why is this called recipients? 
    //Should it not be issuers?
    jws.recipient(jwsKey, { typ: 'JWM', kid: jwsKey.kid, alg: 'ES256' });

    const jwsCompactOutput = jws.sign("compact");
    const jwsJsonOutput = jws.sign("general");

    console.log("------------------- SIGNATURE -------------------");
    console.log("JWS Compact Output: ");
    console.log(jwsCompactOutput);

    console.log("JWS General Output: ");
    console.log(JSON.stringify(jwsJsonOutput, null, 2));

    console.log("JWS Header Output: ");
    console.log(JSON.stringify(JSON.parse(base64url.decode(jwsJsonOutput.signatures[0].protected)), null, 2));

    //Prepare JWE(signed_payload)

    //Get recipient key
    const recipientJWK = JSON.parse(await fs.readFile("example-keys/bob.json"));
    const jweKey = jose.JWK.asKey(recipientJWK);

    //Prepare JweJson
    const jweJson = new jose.JWE.Encrypt(
        JSON.stringify(jwsJsonOutput),
        {
            typ: 'JWM',
            enc: "A256GCM",
            kid: jweKey.kid,
            alg: 'ECDH-ES+A256KW'
        });
    
    // Prepare JweCompact
    const jweCompact = new jose.JWE.Encrypt(
        jwsCompactOutput,
        {
            typ: 'JWM',
            enc: "A256GCM",
            kid: jweKey.kid,
            alg: 'ECDH-ES+A256KW'
        });

    //Encrypt JSON to single recipient
    jweJson.recipient(jweKey);

    // Encrypt compact to single recipient
    jweCompact.recipient(jweKey);

    //Produce the general serialization of the JWM
    const nestedJwmGeneral = jweJson.encrypt('general');
    const nestedJwmCompact = jweCompact.encrypt('compact');

    console.log("------------------- ENCRYPTION -------------------");
    console.log("JWE General serialization:");
    console.log(JSON.stringify(nestedJwmGeneral, null, 2));

    console.log("JWE Compact serialization:");
    console.log(nestedJwmCompact);

    const protectedHeader = JSON.parse(base64url.decode(nestedJwmGeneral.protected));

    console.log("Header:");
    console.log(JSON.stringify(protectedHeader, null, 2));

}

main();
