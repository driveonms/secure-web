function wordArrayToBase64(wordArray) {
  return CryptoJS.enc.Base64.stringify(wordArray);
}
function base64ToWordArray(base64) {
  return CryptoJS.enc.Base64.parse(base64);
}

// Encrypt with salt and IV, output bundle
function handleEncrypt() {
  var password = document.getElementById("encPass").value;
  var plaintext = document.getElementById("encText").value;
  if (!plaintext || !password) {
    document.getElementById("encBundle").value = "Must enter text and password.";
    return;
  }
  var salt = CryptoJS.lib.WordArray.random(16);
  var iv = CryptoJS.lib.WordArray.random(16);
  var key = CryptoJS.PBKDF2(password, salt, { keySize: 256/32, iterations: 100000 });
  var encrypted = CryptoJS.AES.encrypt(plaintext, key, { iv: iv });
  var encryptedBytes = salt.clone().concat(iv).concat(encrypted.ciphertext);
  var bundle = wordArrayToBase64(encryptedBytes);
  document.getElementById("encBundle").value = bundle;
}

// Decrypt from bundle, require password
function handleDecrypt() {
  var password = document.getElementById("decPass").value;
  var bundle = document.getElementById("decBundle").value;
  if (!bundle || !password) {
    document.getElementById("decText").value = "Must enter bundle and password.";
    return;
  }
  try {
    var encryptedBytes = base64ToWordArray(bundle);
    var salt = CryptoJS.lib.WordArray.create(encryptedBytes.words.slice(0, 4), 16);
    var iv = CryptoJS.lib.WordArray.create(encryptedBytes.words.slice(4, 8), 16);
    var ciphertext = CryptoJS.lib.WordArray.create(encryptedBytes.words.slice(8), encryptedBytes.sigBytes - 32);
    var key = CryptoJS.PBKDF2(password, salt, { keySize: 256/32, iterations: 100000 });
    var decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertext }, key, { iv: iv });
    var plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    document.getElementById("decText").value = plaintext ? plaintext : "Decryption failed.";
  } catch (e) {
    document.getElementById("decText").value = "Decryption failed.";
  }
}
