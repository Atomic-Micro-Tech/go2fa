// go2fa mendemonstrasikan penggunaan TOTP (RFC 6238) dengan paket
// github.com/pquerna/otp, kompatibel dengan Google Authenticator dan
// aplikasi authenticator lainnya.
package main

import (
	"fmt"
	"image/png"
	"os"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func main() {
	// 1. Buat secret TOTP. Issuer dan AccountName akan tampil di aplikasi
	// authenticator user sehingga akunnya mudah dikenali.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "go2fa",
		AccountName: "budi@example.com",
		Period:      30,                // detik per jendela kode (standar TOTP)
		Digits:      otp.DigitsSix,     // kode 6 digit
		Algorithm:   otp.AlgorithmSHA1, // didukung semua aplikasi authenticator
	})

	if err != nil {

		panic(err)
	}

	// Secret base32: inilah yang disimpan server dan dipakai untuk
	// memverifikasi kode yang dikirim user. Jangan pernah dikirim ke client.
	fmt.Println("secret  :", key.Secret())

	// URL otpauth:// diberikan ke user untuk ditambahkan ke aplikasi
	// authenticator — biasanya lewat QR code.
	fmt.Println("otpauth :", key.URL())

	// QR code dari URL di atas; simpan sebagai PNG lalu scan dengan HP.
	img, err := key.Image(256, 256)

	if err != nil {

		panic(err)
	}

	f, err := os.Create("qr.png")

	if err != nil {

		panic(err)
	}

	defer f.Close()

	err = png.Encode(f, img)

	if err != nil {

		panic(err)
	}

	fmt.Println("qr code : ditulis ke qr.png")

	// 2. Hitung kode untuk waktu sekarang — angka ini pula yang tampil di
	// aplikasi authenticator user dan berganti tiap key.Period() detik.
	code, err := totp.GenerateCode(key.Secret(), time.Now())

	if err != nil {

		panic(err)
	}

	fmt.Printf("kode    : %s (pada %s)\n", code, time.Now().Format("15:04:05"))

	// 3. Verifikasi kode yang dikirim user saat login.
	fmt.Println("kode benar diterima  :", totp.Validate(code, key.Secret()))
	fmt.Println("kode salah ditolak   :", totp.Validate("000000", key.Secret()))

	// 4. ValidateCustom memberi toleransi skew: kode dari jendela waktu
	// sebelumnya/berikutnya tetap diterima, karena jam HP user bisa
	// selisih beberapa detik dari jam server.
	valid, err := totp.ValidateCustom(code, key.Secret(), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // toleransi ±1 jendela (±30 detik)
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {

		panic(err)
	}

	fmt.Println("validate custom      :", valid)
}
