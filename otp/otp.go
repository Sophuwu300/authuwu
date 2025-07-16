package otp

import (
	"github.com/pquerna/otp/totp"
)

func (u *User) NewOTP() (string, error) {
	otp, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "authuwu.sophuwu.com",
		AccountName: u.Username,
	})
	if err != nil {
		return "", err
	}
	u.OTP = otp.Secret()
	return otp.URL(), nil
}

func (u *User) CheckOTP(otp string) bool {
	return totp.Validate(otp, u.OTP)
}

type User struct {
	Username string `storm:"id,unique,index"`
	OTP      string
}
