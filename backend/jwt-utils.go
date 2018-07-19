package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/digitalrebar/provision/models"
)

func randString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Printf("Failed to read random\n")
		return "ARGH!"
	}
	base64 := base64.URLEncoding.EncodeToString(b)
	return base64[:n]
}

// Config configures a Manager.
type JwtConfig struct {
	// digital signing method, defaults to jwt.SigningMethodHS256 (SHA256)
	Method jwt.SigningMethod
}

// Manager is a JSON Web Token (JWT) Provider which create or retrieves tokens
// with a particular signing key and options.
type JwtManager struct {
	key    []byte
	method jwt.SigningMethod
}

// New creates a new Manager which provides JWTs using the given signing key.
// Defaults to signing with SHA256 HMAC (jwt.SigningMethodHS256)
func NewJwtManager(key []byte, configs ...JwtConfig) *JwtManager {
	var c JwtConfig
	if len(configs) == 0 {
		c = JwtConfig{}
	} else {
		c = configs[0]
	}
	m := &JwtManager{
		key:    key,
		method: c.Method,
	}
	m.setDefaults()
	return m
}

func (m *JwtManager) updateKey(newkey []byte) {
	m.key = newkey
}

func (m *JwtManager) setDefaults() {
	if m.method == nil {
		m.method = jwt.SigningMethodHS256
	}
}

// getKey accepts an unverified JWT and returns the signing/verification key.
// Also ensures tha the token's algorithm matches the signing method expected
// by the manager.
func (m *JwtManager) getKey(unverified *jwt.Token) (interface{}, error) {
	// require token alg to match the set signing method, do not allow none
	if meth := unverified.Method; meth == nil || meth.Alg() != m.method.Alg() {
		return nil, jwt.ErrHashUnavailable
	}
	return m.key, nil
}

func encrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))

	// iv =  initialization vector
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, b64ciphertext string) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.URLEncoding.DecodeString(b64ciphertext)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return "", err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// Sign digitally signs a *jwt.Token using the token's method and the manager's
// signing key to return a string
func (m *JwtManager) sign(token *jwt.Token) (string, error) {
	jwtString, err := token.SignedString(m.key)
	if err != nil {
		return "", err
	}

	return encrypt(m.key, jwtString)
}

//
// Grantor Claims allow for the token to be validated against
// the granting user, the current user, and the machine.
// Each of those object can have a secret that if changed
// on the user object will invalid the token.
//
// This allows for mass revocation at a machine, grantor,
// or user level.
//
type GrantorClaims struct {
	GrantorId     string `json:"grantor_id"`
	GrantorSecret string `json:"grantor_secret"`
	UserId        string `json:"user_id"`
	UserSecret    string `json:"user_secret"`
	MachineUuid   string `json:"machine_uuid"`
	MachineSecret string `json:"machine_secret"`
}

// If present, we should validate them.
func (gc *GrantorClaims) Validate(grantor, user, machine string) bool {
	if gc.GrantorSecret != "" && grantor != "" && grantor != gc.GrantorSecret {
		return false
	}
	if gc.UserSecret != "" && user != "" && user != gc.UserSecret {
		return false
	}
	if gc.MachineSecret != "" && machine != "" && machine != gc.MachineSecret {
		return false
	}
	return true
}

// DrpCustomClaims is a JWT token that contains a list of all the
// things this token allows access to.
type DrpCustomClaims struct {
	DrpClaims     []*models.Claim `json:"drp_claims"`
	DrpRoles      []string
	GrantorClaims GrantorClaims `json:"grantor_claims"`
	jwt.StandardClaims
}

func (d *DrpCustomClaims) ClaimsList(rt *RequestTracker) []models.Claims {
	res := []models.Claims{}
	if len(d.DrpClaims) > 0 {
		res = append(res, (&models.Role{Claims: d.DrpClaims}).Compile())
	}
	if len(d.DrpRoles) > 0 {
		for _, rName := range d.DrpRoles {
			if r := rt.find("roles", rName); r != nil {
				res = append(res, AsRole(r).CompiledClaims())
			}
		}
	}
	return res
}

func (d *DrpCustomClaims) match(rt *RequestTracker, r *models.Role) bool {
	wantedClaim := r.Compile()
	for _, authedClaim := range d.ClaimsList(rt) {
		if authedClaim.Contains(wantedClaim) {
			return true
		}
	}
	return false
}

func (d *DrpCustomClaims) HasGrantorId() bool {
	return d.GrantorClaims.GrantorId != ""
}
func (d *DrpCustomClaims) GrantorId() string {
	return d.GrantorClaims.GrantorId
}
func (d *DrpCustomClaims) HasUserId() bool {
	return d.GrantorClaims.UserId != ""
}
func (d *DrpCustomClaims) UserId() string {
	return d.GrantorClaims.UserId
}
func (d *DrpCustomClaims) HasMachineUuid() bool {
	return d.GrantorClaims.MachineUuid != ""
}
func (d *DrpCustomClaims) MachineUuid() string {
	return d.GrantorClaims.MachineUuid
}

func (d *DrpCustomClaims) ValidateSecrets(grantor, user, machine string) bool {
	return d.GrantorClaims.Validate(grantor, user, machine)
}

// NewClaim creates a new, unsigned Token that doesn't allow access to anything.
// You must call Seal() to turn this into a signed JWT token.
func NewClaim(user, grantor string, ttl time.Duration) *DrpCustomClaims {
	res := &DrpCustomClaims{DrpClaims: []*models.Claim{}, DrpRoles: []string{}}
	res.IssuedAt = time.Now().Unix()
	res.ExpiresAt = time.Now().Add(ttl).Unix()
	res.Issuer = "digitalrebar provision"
	res.Id = user
	res.GrantorClaims.UserId = user
	res.GrantorClaims.GrantorId = grantor
	return res
}

// Set the specific secrets
func (d *DrpCustomClaims) AddMachine(uuid string) *DrpCustomClaims {
	d.GrantorClaims.MachineUuid = uuid
	return d
}

// Set the specific secrets
func (d *DrpCustomClaims) AddSecrets(user, grantor, machine string) *DrpCustomClaims {
	d.GrantorClaims.UserSecret = user
	d.GrantorClaims.GrantorSecret = grantor
	d.GrantorClaims.MachineSecret = machine
	return d
}

// AddRawClaim adds a discrete Claim to our custom Token class.
func (d *DrpCustomClaims) AddRawClaim(scope, action, specific string) *DrpCustomClaims {
	d.DrpClaims = append(d.DrpClaims, &models.Claim{Scope: scope, Action: action, Specific: specific})
	return d
}

func (d *DrpCustomClaims) AddRoles(names ...string) *DrpCustomClaims {
	d.DrpRoles = append(d.DrpRoles, names...)
	return d
}

// Seal turns our custom Token class into a signed JWT Token.
func (d *DrpCustomClaims) Seal(m *JwtManager) (string, error) {
	return m.sign(jwt.NewWithClaims(m.method, d))
}

// Get gets the signed JWT from the Authorization header. If the token is
// missing, expired, or the signature does not validate, returns an error.
func (m *JwtManager) get(encTokenString string) (*DrpCustomClaims, error) {
	tokenString, err := decrypt(m.key, encTokenString)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &DrpCustomClaims{}, m.getKey)
	if err != nil {
		return nil, err
	}

	if drpCustomClaim, ok := token.Claims.(*DrpCustomClaims); !ok {
		return nil, errors.New(fmt.Sprintf("Missing claim structure: %v\n", token))
	} else {
		return drpCustomClaim, nil
	}
}
