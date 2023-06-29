const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const CryptoJS = require("crypto-js");
const keytar = require("keytar");
const Zip = require("adm-zip");

function getContentKey(datFilePath, format, env) {
    const { deviceId } = env;
    if (format === "bom") {
        return deviceId.substr(2, 16);
    } else {
        const data = fs.readFileSync(datFilePath);
        const key = CryptoJS.enc.Utf8.parse(deviceId.substr(0, 16));
        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.lib.WordArray.create(data.subarray(16)),
        });
        const options = {
            iv: CryptoJS.lib.WordArray.create(data.subarray(0, 16)),
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.NoPadding,
        };
        const decrypted = CryptoJS.AES.decrypt(cipherParams, key, options);
        return CryptoJS.enc.Utf8.stringify(decrypted).substr(
            deviceId.length + 32,
            16
        );
    }
}

async function decryptContent(data, key) {
    key = new TextEncoder().encode(key);
    key = await crypto.subtle.importKey("raw", key, "AES-CBC", true, [
        "decrypt",
    ]);
    return Buffer.from(
        await crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: data.subarray(0, 16),
            },
            key,
            data.subarray(16)
        )
    );
}

function decryptData(data, secretKey) {
    const { length } = secretKey;
    const key = CryptoJS.enc.Utf8.parse(secretKey);
    if (length % 16 !== 0) {
        CryptoJS.pad.Pkcs7.pad(key, 4);
    }
    const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: CryptoJS.lib.WordArray.create(data),
    });
    const options = {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
    };
    const decrypted = CryptoJS.AES.decrypt(cipherParams, key, options);
    const plainText = CryptoJS.enc.Utf8.stringify(decrypted);
    return plainText;
}

function decryptGlobalData(data, secretKey) {
    const text = decryptData(data.subarray(256), secretKey);
    return JSON.parse(text);
}

function decryptUserData(data, username) {
    const r = data.readUInt16BE(72);
    const n = data.subarray(8, 8 + r).toString();
    const hash = CryptoJS.SHA1(`${n}-${username}`);
    const secretKey = CryptoJS.enc.Hex.stringify(hash).substr(2, 16);
    const text = decryptData(data.subarray(256), secretKey);
    return JSON.parse(text);
}

function getAppDataPath() {
    const platform = process.platform;
    const home = process.env.HOME;
    const appName = "Ridibooks";
    let appData = "";
    switch (platform) {
        case "darwin":
            appData = path.join(home, "Library/Application Support");
            break;
        case "win32":
            appData = process.env.APPDATA || path.join(home, "AppData/Roaming");
            break;
        default:
            throw new Error(
                `Unable to find matching app data path for platform ${platform}.`
            );
    }
    return path.join(appData, appName);
}

async function getSecretKey() {
    const password = await keytar.getPassword("com.ridi.books", "global");
    return Buffer.from(password, "base64").toString();
}

function getTitle(book, id) {
    return book.downloaded[id].title.main;
}

function getFormat(book, id) {
    return book.downloaded[id].format;
}

async function decryptZip(id, key, dstDirPath, env) {
    const { book, libraryPath } = env;
    const zipFilePath = path.join(libraryPath, id, `${id}.zip`);
    const zip = new Zip(zipFilePath);
    const ext = [".jpg", ".jpeg", ".png", ".bmp", ".gif"];
    const acc = new Zip();
    for (const entry of zip.getEntries()) {
        if (!entry.isDirectory && ext.includes(path.extname(entry.entryName))) {
            const data = zip.readFile(entry);
            acc.addFile(entry.entryName, await decryptContent(data, key));
        }
    }
    const dstFilePath = path.join(
        dstDirPath,
        `${id} ${getTitle(book, id)}.zip`
    );
    acc.writeZip(dstFilePath);
}

async function decryptEpub(id, key, dstDirPath, env) {
    const { book, libraryPath } = env;
    const epubFilePath = path.join(libraryPath, id, `${id}.epub`);
    const data = fs.readFileSync(epubFilePath);
    const dstFilePath = path.join(
        dstDirPath,
        `${id} ${getTitle(book, id)}.epub`
    );
    fs.writeFileSync(dstFilePath, await decryptContent(data, key));
}

async function decryptPdf(id, key, dstDirPath, env) {
    const { book, libraryPath } = env;
    const pdfFilePath = path.join(libraryPath, id, `${id}.pdf`);
    const data = fs.readFileSync(pdfFilePath);
    const dstFilePath = path.join(
        dstDirPath,
        `${id} ${getTitle(book, id)}.pdf`
    );
    fs.writeFileSync(dstFilePath, await decryptContent(data, key));
}

function decrypt(id, format, dstDirPath, env) {
    const { libraryPath } = env;
    const datFilePath = path.join(libraryPath, id, `${id}.dat`);
    const key = getContentKey(datFilePath, format, env);
    switch (format) {
        case "bom":
            decryptZip(id, key, dstDirPath, env);
            break;
        case "epub":
            decryptEpub(id, key, dstDirPath, env);
            break;
        case "pdf":
            decryptPdf(id, key, dstDirPath, env);
            break;
    }
}

function show(env) {
    for (const e of Object.values(env.book.downloaded)) {
        console.log(`${e.id} ${e.title.main} ${e.format}`);
    }
}

(async function () {
    if (process.argv[2] !== "show" && process.argv[2] !== "decrypt") {
        console.log("Usages:");
        console.log("  node main show <ridi username>");
        console.log(
            "  node main decrypt <ridi username> <destination directory> <book id>"
        );
        process.exit(1);
    }
    const secretKey = await getSecretKey();
    const username = process.argv[3];
    const appDataPath = getAppDataPath();
    const deviceFilePath = path.join(
        appDataPath,
        "datastores",
        "global",
        "device"
    );
    const deviceId = decryptGlobalData(
        fs.readFileSync(deviceFilePath),
        secretKey
    ).device.deviceId;
    const bookFilePath = path.join(
        appDataPath,
        "datastores",
        "user",
        username,
        "book"
    );
    const book = decryptUserData(fs.readFileSync(bookFilePath), username);
    // TODO: load library directory from preference file if exists.
    const libraryPath = path.join(appDataPath, "library", username);
    const env = { deviceId, book, libraryPath };
    switch (process.argv[2]) {
        case "show":
            show(env);
            break;
        case "decrypt":
            decrypt(
                process.argv[5],
                getFormat(book, process.argv[5]),
                process.argv[4],
                env
            );
            break;
    }
})();
