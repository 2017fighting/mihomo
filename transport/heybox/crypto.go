// Package heybox 实现小黑盒加速器（HeyBoxAcc）加速节点连接协议与账号 API 客户端。
//
// 协议为魔改 SOCKS5 单包握手（无方法协商、密码在前、VER=9/10 整体 AES-128-CBC+base64），
// 数据面 UDP 为 gost 风格扩展头。协议逆向细节见 PROTOCOL.md（heybox_acc 仓库）；
// goimpl/ 为独立参考实现，本包在其基础上适配 mihomo 的拨号与生命周期。
package heybox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"time"
)

// 原版 heyboxutils 包中的硬编码密钥（均为 16 字节 ASCII，AES-128）。
const (
	// KeyVer9 是 VER=9 握手加密密钥，也用于本地登录凭据落盘加密（已由真实抓包握手包解密验证）。
	KeyVer9 = "39642ed864ee7afe"
	// KeyConfigResult 是 accapi 各接口响应 result 字段的解密密钥。
	KeyConfigResult = "22962ed867ee7cff"
)

// padding 标准 PKCS#7。
func padding(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return data
	}
	n := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

func unpadding(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("heybox: invalid padded length")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, errors.New("heybox: invalid PKCS7 padding")
	}
	for _, c := range data[len(data)-n:] {
		if int(c) != n {
			return nil, errors.New("heybox: invalid PKCS7 padding")
		}
	}
	return data[:len(data)-n], nil
}

// EncryptAES 对应 heyboxutils.EncryptAES：AES-128-CBC，IV == key，PKCS#7 填充，
// 结果 Base64(Std) 编码。注意：返回的是 base64 文本的字节，线上长度字段即该文本长度。
func EncryptAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := padding(data, block.BlockSize())
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, key[:block.BlockSize()]).CryptBlocks(ct, padded)
	return []byte(base64.StdEncoding.EncodeToString(ct)), nil
}

// DecryptAES 对应 heyboxutils.DecryptAES（EncryptAES 的逆），输入为 base64 文本。
func DecryptAES(key, data []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw)%block.BlockSize() != 0 {
		return nil, errors.New("heybox: ciphertext is not block-aligned")
	}
	pt := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, key[:block.BlockSize()]).CryptBlocks(pt, raw)
	return unpadding(pt, block.BlockSize())
}

// DecryptConfigResult 解密 accapi 响应的 result 字段。
func DecryptConfigResult(result string) ([]byte, error) {
	return DecryptAES([]byte(KeyConfigResult), []byte(result))
}

var rndMu sync.Mutex

// generateHandshakeRandom 对应 heyboxutils.GenerateSocksHandShakeRandomBytes：
// UnixNano 种子 PRNG 取 int32，以 ":%d" 拼入握手密码串。可注入以便测试。
var generateHandshakeRandom = func() ([]byte, int32) {
	rndMu.Lock()
	defer rndMu.Unlock()
	time.Sleep(time.Nanosecond)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	v := int32(r.Int63())
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b, v
}
