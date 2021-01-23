package aes256ecb

import (
    "bytes"
    "testing"
)
import "github.com/stretchr/testify/assert"

func TestEncrypt(t *testing.T) {
    key := []byte("123")
    text := []byte("0123456789012345678901234567890123456789")
    str := Encrypt2Base64(key,text)
    t.Log(str)
    b,e := DecryptFromBase64(key,str)
    if e != nil {
        t.Fatal(e)
    }
    assert.True(t, bytes.Equal(b,text),"no true")
    t.Log(string(b))
}
