package aes256ecb

import (
    "bytes"
    "crypto/aes"
    "encoding/base64"
)

func Encrypt2Base64(passwd []byte, data []byte) string {
    secret := Encrypt(passwd, data)
    return base64.StdEncoding.EncodeToString(secret)
}

func DecryptFromBase64(passwd []byte, data string) ([]byte,error) {
    rawData, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return nil, err
    }
    text := Decrypt(passwd,rawData)
    return text,nil
}

// Encrypt text to cipher text
func Encrypt(key []byte, text []byte) []byte {
    c,_ := aes.NewCipher(PasswdPadding(key))
    paddingText := PKCS7Padding(text)
    cipherText := make([]byte, len(paddingText))
    for st,ed := 0, aes.BlockSize; ed <= len(paddingText); st,ed = st+aes.BlockSize, ed+aes.BlockSize {
        c.Encrypt(cipherText[st:ed], paddingText[st:ed])
    }
    return cipherText
}

// Decrypt cipher text to text
func Decrypt(key []byte, cipherText []byte) []byte {
    c,_:= aes.NewCipher(PasswdPadding(key))
    paddingText := make([]byte, len(cipherText))
    for st,ed := 0, aes.BlockSize; ed <= len(paddingText); st,ed = st+aes.BlockSize, ed+aes.BlockSize {
        c.Decrypt(paddingText[st:ed], cipherText[st:ed])
    }
    return PKCS7UnPadding(paddingText)
}

// Fill 0x00 if the length of key less than 32
func PasswdPadding(key []byte) []byte {
    ret := make([]byte, 32)
    copy(ret, key)
    return ret
}

// Fill bytes until the length is an integer multiple of 16 again
func PKCS7Padding(text []byte) []byte {
    padding := 16 - len(text) % 16
    paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(text, paddingText...)
}

// UnPadding
func PKCS7UnPadding(text []byte) []byte {
    length   := len(text)
    if length < 16 || text[length-1] > 16 {
        return nil
    }
    unPadding := int(text[length-1])
    ed := length - unPadding
    return text[:ed]
}