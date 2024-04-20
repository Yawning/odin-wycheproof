package wycheproof

import "core:bytes"
import "core:encoding/hex"
import "core:encoding/json"
import "core:log"
import "core:os"

HexBytes :: string

hexbytes_compare :: proc(x: HexBytes, b: []byte, allocator := context.allocator) -> bool {
	dst := hexbytes_decode(x)
	defer delete(dst)

	return bytes.equal(dst, b)
}

hexbytes_decode :: proc(x: HexBytes, allocator := context.allocator) -> []byte {
	dst, ok := hex.decode(transmute([]byte)(x), allocator)
	if !ok {
		panic("wycheproof/common/HexBytes: invalid hex encoding")
	}

	return dst
}

Result :: string

result_check :: proc(r: Result, ok: bool, is_strict := true) -> bool {
	switch r {
	case "valid":
		return ok
	case "invalid":
		return !ok
	case "acceptable":
		return !is_strict && ok
	case:
		panic("wycheproof/common/Result: invalid result string")
	}
}

result_is_valid :: proc(r: Result) -> bool {
	return r == "valid"
}

// The type namings are not following Odin convention, to better match
// the schema, though the fields do.

load :: proc(tvs: ^$T/TestVectors, fn: string) -> bool {
	raw_json, ok := os.read_entire_file(fn)
	if !ok {
		log.error("failed to load raw JSON")
		return false
	}

	if err := json.unmarshal(raw_json, tvs); err != nil {
		log.errorf("failed to parse JSON: %v", err)
		return false
	}

	return true
}

TestVectors :: struct($TestGroup: typeid) {
	algorithm:         string `json:"algorithm"`,
	generator_version: string `json:"generatorVersion"`,
	number_of_tests:   int `json:"numberOfTests"`,
	header:            []string `json:"header"`,
	notes:             map[string]TestVectorsNote `json:"notes"`,
	schema:            string `json:"schema"`,
	test_groups:       []TestGroup `json:"testGroups"`,
}

TestVectorsNote :: struct {
	bug_type:    string `json:"bugType"`,
	description: string `json:"description"`,
	links:       []string `json:"links"`,
}

AeadTestGroup :: struct {
	iv_size:  int `json:"ivSize"`,
	key_size: int `json:"keySize"`,
	tag_size: int `json:"tagSize"`,
	tests:    []AeadTestVector `json:"tests"`,
}

AeadTestVector :: struct {
	tc_id:   int `json:"tcId"`,
	comment: string `json:"comment"`,
	key:     HexBytes `json:"key"`,
	iv:      HexBytes `json:"iv"`,
	aad:     HexBytes `json:"aad"`,
	msg:     HexBytes `json:"msg"`,
	ct:      HexBytes `json:"ct"`,
	tag:     HexBytes `json:"tag"`,
	result:  Result `json:"result"`,
	flags:   []string `json:"flags"`,
}

HkdfTestGroup :: struct {
	key_size: int `json:"keySize"`,
	tests:    []HkdfTestVector `json:"tests"`,
}

HkdfTestVector :: struct {
	tc_id:   int `json:"tcId"`,
	comment: string `json:"comment"`,
	ikm:     HexBytes `json:"ikm"`,
	salt:    HexBytes `json:"salt"`,
	info:    HexBytes `json:"info"`,
	size:    int `json:"size"`,
	okm:     HexBytes `json:"ikm"`,
	result:  Result `json:"result"`,
	flags:   []string `json:"flags"`,
}

MacTestGroup :: struct {
	key_size: int `json:"keySize"`,
	tag_size: int `json:"tagSize"`,
	tests:    []MacTestVector `json:"tests"`,
}

MacTestVector :: struct {
	tc_id:   int `json:"tcId"`,
	comment: string `json:"comment"`,
	key:     HexBytes `json:"key"`,
	msg:     HexBytes `json:"msg"`,
	tag:     HexBytes `json:"tag"`,
	result:  Result `json:"result"`,
	flags:   []string `json:"flags"`,
}

XdhTestGroup :: struct {
	curve: string `json:"curve"`,
	tests: []XdhTestVector `json:"tests"`,
}

XdhTestVector :: struct {
	tc_id:   int `json:"tcId"`,
	comment: string `json:"comment"`,
	public:  HexBytes `json:"public"`,
	private: HexBytes `json:"private"`,
	shared:  HexBytes `json:"shared"`,
	result:  Result `json:"result"`,
	flags:   []string `json:"flags"`,
}

EddsaTestGroup :: struct {
	public_key:     EddsaKey `json:"publicKey"`,
	public_key_der: HexBytes `json:"publicKeyDer"`,
	public_key_pem: string `json:"publicKeyPem"`,
	public_key_jwk: EddsaJwk `json:"publicKeyJwk"`,
	type:           string `json:"type"`,
	tests:          []EddsaTestVector `json:"tests"`,
}

EddsaKey :: struct {
	type:     string `json:"type"`,
	curve:    string `json:"curve"`,
	key_size: int `json:"keySize"`,
	pk:       HexBytes `json:"pk"`,
}

EddsaJwk :: struct {
	kid: string `json:"kid"`,
	crv: string `json:"crv"`,
	kty: string `json:"kty"`,
	x:   string `json:"x"`,
}

EddsaTestVector :: struct {
	tc_id:   int `json:"tcId"`,
	comment: string `json:"comment"`,
	msg:     HexBytes `json:"msg"`,
	sig:     HexBytes `json:"sig"`,
	result:  Result `json:"result"`,
	flags:   []string `json:"flags"`,
}

PbkdfTestGroup :: struct {
	type:  string `json:"type"`,
	tests: []PbkdfTestVector `json:"tests"`,
}

PbkdfTestVector :: struct {
	tc_id:           int `json:"tcId"`,
	comment:         string `json:"comment"`,
	password:        HexBytes `json:"password"`,
	salt:            HexBytes `json:"salt"`,
	iteration_count: u32 `json:"iterationCount"`,
	dk_len:          int `json:"dkLen"`,
	dk:              HexBytes `json:"dk"`,
	result:          Result `json:"result"`,
	flags:           []string `json:"flags"`,
}
