package main

import "core:encoding/hex"
import "core:log"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"

import chacha_simd128 "core:crypto/_chacha20/simd128"
import chacha_simd256 "core:crypto/_chacha20/simd256"
import "core:crypto/aegis"
import "core:crypto/aes"
import "core:crypto/chacha20"
import "core:crypto/chacha20poly1305"
import "core:crypto/ed25519"
import "core:crypto/hkdf"
import "core:crypto/hmac"
import "core:crypto/kmac"
import "core:crypto/pbkdf2"
import "core:crypto/siphash"
import "core:crypto/x25519"
import "core:crypto/x448"

import "wycheproof"

// Covered:
// - crypto/aegis
//   - aegis128L_test.json
//   - aegis256_test.json
// - crypto/aes
//   - aes_gcm_test.json
// - crypto/chacha20poly1305
//   - chacha20_poly1305_test.json
//   - xchacha20_poly1305_test.json
// - crypto/ed25519
//   - ed25519_test.json
// - crypto/hkdf
//   - hkdf_sha1_test.json
//   - hkdf_sha256_test.json
//   - hkdf_sha384_test.json
//   - hkdf_sha512_test.json
// - crypto/hmac (Note: We do not implement SHA-512/224)
//   - hmac_sha1_test.json
//   - hmac_sha224_test.json
//   - hmac_sha256_test.json
//   - hmac_sha3_224_test.json
//   - hmac_sha3_256_test.json
//   - hmac_sha3_384_test.json
//   - hmac_sha3_512_test.json
//   - hmac_sha384_test.json
//   - hmac_sha512_224_test.json
//   - hmac_sha512_256_test.json
//   - hmac_sha512_test.json
//   - hmac_sm3_test.json
// - crypto/kmac
//   - kmac128_no_customization_test.json
//   - kmac256_no_customization_test.json
// - crypto/pbkdf2
//   - pbkdf2_hmacsha1_test.json
//   - pbkdf2_hmacsha224_test.json
//   - pbkdf2_hmacsha256_test.json
//   - pbkdf2_hmacsha384_test.json
//   - pbkdf2_hmacsha512_test.json
// - crypto/siphash
//   - siphash_1_3_test.json
//   - siphash_2_4_test.json
//   - siphash_4_8_test.json
// - crypto/x25519
//   - x25519_test.json
// - crypto/x448
//   - x448_test.json
//
// Not covered (not in wycheproof):
// - crypto/blake2b
// - crypto/blake2s
// - crypto/legacy/keccak
// - crypto/legacy/md5
// - crypto/tuplehash

ARENA_SIZE :: 4 * 1024 * 1024 // There is no kill like overkill.
SUFFIX_TEST_JSON :: "_test.json"

main :: proc() {
	context.logger = log.create_console_logger(lowest = env_to_log_level())

	if len(os.args) < 2 {
		log.error("expecting path to wycheproof directory")
		os.exit(1)
	}

	base_path := filepath.join([]string{os.args[1], "testvectors_v1"})
	fi, err := os.stat(base_path)
	if err != os.ERROR_NONE {
		log.errorf("failed to stat wycheproof testvectors directory '%s': %+v", base_path, err)
		os.exit(1)
	}
	if !fi.is_dir {
		log.errorf("wycheproof testvectors directory, isn't '%s'", base_path)
		os.exit(1)
	}
	delete(base_path)

	base_path = fi.fullpath
	log.infof("wycheproof path: %s", base_path)

	// Setup the arena allocator, and make it the context allocator.
	//
	// It is safe to call `mem.free_all()`, without shitting on the
	// path to the test vectors, because that will clean up the arena.
	arena: mem.Arena
	mem.arena_init(&arena, make([]byte, ARENA_SIZE))
	context.allocator = mem.arena_allocator(&arena)

	// Run the tests.
	all_ok := true
	test_fns := []test_proc {
		test_aead_aegis,
		test_aead_aes_gcm,
		test_aead_chacha20_poly1305,
		test_eddsa_ed25519,
		test_hkdf,
		test_mac,
		test_pbkdf2,
		test_xdh,
	}
	for fn in test_fns {
		all_ok &= fn(base_path)
		log.debugf("arena stats: peak_used: %d", arena.peak_used)
		mem.free_all()
	}

	if !all_ok {
		os.exit(1)
	}
}

test_proc :: proc(_: string) -> bool

supported_aegis_impls :: proc() -> [dynamic]aes.Implementation {
	impls := make([dynamic]aes.Implementation, 0, 2, context.temp_allocator)
	append(&impls, aes.Implementation.Portable)
	if aegis.is_hardware_accelerated() {
		append(&impls, aes.Implementation.Hardware)
	}

	return impls
}

test_aead_aegis :: proc(base_path: string) -> bool {
	files := []string {
		"aegis128L_test.json",
		"aegis256_test.json",
	}

	log.debug("aead/aegis: starting")

	allOk := true
	for f, i in files {
		mem.free_all() // Probably don't need this, but be safe.

		fn := filepath.join([]string{base_path, f})

		test_vectors: wycheproof.TestVectors(wycheproof.AeadTestGroup)
		if !wycheproof.load(&test_vectors, fn) {
			allOk &= false
			continue
		}

		for impl in supported_aegis_impls() {
			allOk &= test_aead_aegis_impl(&test_vectors, impl)
		}
	}

	return allOk
}

test_aead_aegis_impl :: proc(
	test_vectors: ^wycheproof.TestVectors(wycheproof.AeadTestGroup),
	impl: aes.Implementation,
) -> bool {
	log.debug("aead/aegis/%v: starting", impl)

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group in test_vectors.test_groups {
		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf(
					"aead/aegis/%v/%d: %s: %+v",
					impl,
					test_vector.tc_id,
					comment,
					test_vector.flags,
				)
			} else {
				log.debugf("aead/aegis/%v/%d: %+v",
					impl,
					test_vector.tc_id,
					test_vector.flags,
				)
			}

			key := wycheproof.hexbytes_decode(test_vector.key)
			iv := wycheproof.hexbytes_decode(test_vector.iv)
			aad := wycheproof.hexbytes_decode(test_vector.aad)
			msg := wycheproof.hexbytes_decode(test_vector.msg)
			ct := wycheproof.hexbytes_decode(test_vector.ct)
			tag := wycheproof.hexbytes_decode(test_vector.tag)

			if len(iv) == 0 {
				log.infof(
					"aead/aegis/%v/%d: skipped, invalid IVs panic",
					impl,
					test_vector.tc_id,
				)
				num_skipped += 1
				continue
			}

			ctx: aegis.Context
			aegis.init(&ctx, key, impl)

			if wycheproof.result_is_valid(test_vector.result) {
				ct_ := make([]byte, len(ct))
				tag_ := make([]byte, len(tag))
				aegis.seal(&ctx, ct_, tag_, iv, aad, msg)

				ok := wycheproof.hexbytes_compare(test_vector.ct, ct_)
				if !wycheproof.result_check(test_vector.result, ok) {
					x := transmute(string)(hex.encode(ct_))
					log.errorf(
						"aead/aegis/%v/%d: ciphertext: expected %s actual %s",
						impl,
						test_vector.tc_id,
						test_vector.ct,
						x,
					)
					num_failed += 1
					continue
				}

				ok = wycheproof.hexbytes_compare(test_vector.tag, tag_)
				if !wycheproof.result_check(test_vector.result, ok) {
					x := transmute(string)(hex.encode(tag_))
					log.errorf(
						"aead/aegis/%v/%d: tag: expected %s actual %s",
						impl,
						test_vector.tc_id,
						test_vector.tag,
						x,
					)
					num_failed += 1
					continue
				}
			}

			msg_ := make([]byte, len(msg))
			ok := aegis.open(&ctx, msg_, iv, aad, ct, tag)
			if !wycheproof.result_check(test_vector.result, ok) {
				log.errorf("aead/aegis/%v/%d: decrypt failed", impl, test_vector.tc_id)
				num_failed += 1
				continue
			}

			if ok && !wycheproof.hexbytes_compare(test_vector.msg, msg_) {
				x := transmute(string)(hex.encode(msg_))
				log.errorf(
					"aead/aegis/%v/%d: decrypt msg: expected %s actual %s",
					impl,
					test_vector.tc_id,
					test_vector.msg,
					x,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"aead/aegis: ran %d, passed %d, failed %d, skipped %d",
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}

supported_aes_impls :: proc() -> [dynamic]aes.Implementation {
	impls := make([dynamic]aes.Implementation, 0, 2)
	append(&impls, aes.Implementation.Portable)
	if aes.is_hardware_accelerated() {
		append(&impls, aes.Implementation.Hardware)
	}

	return impls
}

test_aead_aes_gcm :: proc(base_path: string) -> bool {
	fn := filepath.join([]string{base_path, "aes_gcm_test.json"})

	log.debug("aead/aes-gcm: starting")

	test_vectors: wycheproof.TestVectors(wycheproof.AeadTestGroup)
	if !wycheproof.load(&test_vectors, fn) {
		return false
	}

	for impl in supported_aes_impls() {
		if !test_aead_aes_gcm_impl(&test_vectors, impl) {
			return false
		}
	}

	return true
}

test_aead_aes_gcm_impl :: proc(
	test_vectors: ^wycheproof.TestVectors(wycheproof.AeadTestGroup),
	impl: aes.Implementation,
) -> bool {
	log.debug("aead/aes-gcm/%v: starting", impl)

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group in test_vectors.test_groups {
		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf(
					"aead/aes-gcm/%v/%d: %s: %+v",
					impl,
					test_vector.tc_id,
					comment,
					test_vector.flags,
				)
			} else {
				log.debugf("aead/aes-gcm/%v/%d: %+v",
					impl,
					test_vector.tc_id,
					test_vector.flags,
				)
			}

			key := wycheproof.hexbytes_decode(test_vector.key)
			iv := wycheproof.hexbytes_decode(test_vector.iv)
			aad := wycheproof.hexbytes_decode(test_vector.aad)
			msg := wycheproof.hexbytes_decode(test_vector.msg)
			ct := wycheproof.hexbytes_decode(test_vector.ct)
			tag := wycheproof.hexbytes_decode(test_vector.tag)

			if len(iv) == 0 {
				log.infof(
					"aead/aes-gcm/%v/%d: skipped, invalid IVs panic",
					impl,
					test_vector.tc_id,
				)
				num_skipped += 1
				continue
			}

			ctx: aes.Context_GCM
			aes.init_gcm(&ctx, key, impl)

			if wycheproof.result_is_valid(test_vector.result) {
				ct_ := make([]byte, len(ct))
				tag_ := make([]byte, len(tag))
				aes.seal_gcm(&ctx, ct_, tag_, iv, aad, msg)

				ok := wycheproof.hexbytes_compare(test_vector.ct, ct_)
				if !wycheproof.result_check(test_vector.result, ok) {
					x := transmute(string)(hex.encode(ct_))
					log.errorf(
						"aead/aes-gcm/%v/%d: ciphertext: expected %s actual %s",
						impl,
						test_vector.tc_id,
						test_vector.ct,
						x,
					)
					num_failed += 1
					continue
				}

				ok = wycheproof.hexbytes_compare(test_vector.tag, tag_)
				if !wycheproof.result_check(test_vector.result, ok) {
					x := transmute(string)(hex.encode(tag_))
					log.errorf(
						"aead/aes-gcm/%v/%d: tag: expected %s actual %s",
						impl,
						test_vector.tc_id,
						test_vector.tag,
						x,
					)
					num_failed += 1
					continue
				}
			}

			msg_ := make([]byte, len(msg))
			ok := aes.open_gcm(&ctx, msg_, iv, aad, ct, tag)
			if !wycheproof.result_check(test_vector.result, ok) {
				log.errorf("aead/aes-gcm/%v/%d: decrypt failed", impl, test_vector.tc_id)
				num_failed += 1
				continue
			}

			if ok && !wycheproof.hexbytes_compare(test_vector.msg, msg_) {
				x := transmute(string)(hex.encode(msg_))
				log.errorf(
					"aead/aes-gcm/%v/%d: decrypt msg: expected %s actual %s",
					impl,
					test_vector.tc_id,
					test_vector.msg,
					x,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"aead/aes-gcm: ran %d, passed %d, failed %d, skipped %d",
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}

supported_chacha_impls :: proc() -> [dynamic]chacha20.Implementation {
	impls := make([dynamic]chacha20.Implementation, 0, 3)
	append(&impls, chacha20.Implementation.Portable)
	if chacha_simd128.is_performant() {
		append(&impls, chacha20.Implementation.Simd128)
	}
	if chacha_simd256.is_performant() {
		append(&impls, chacha20.Implementation.Simd256)
	}

	return impls
}

test_aead_chacha20_poly1305 :: proc(base_path: string) -> bool {
	files := []string {
		"chacha20_poly1305_test.json",
		"xchacha20_poly1305_test.json",
	}

	log.debug("aead/(x)chacha20poly1305: starting")

	allOk := true
	for f, i in files {
		mem.free_all() // Probably don't need this, but be safe.

		fn := filepath.join([]string{base_path, f})

		test_vectors: wycheproof.TestVectors(wycheproof.AeadTestGroup)
		if !wycheproof.load(&test_vectors, fn) {
			allOk &= false
			continue
		}

		for impl in supported_chacha_impls() {
			allOk &= test_aead_chacha20_poly1305_impl(&test_vectors, i == 1, impl)
		}
	}

	return allOk
}

test_aead_chacha20_poly1305_impl :: proc(
	test_vectors: ^wycheproof.TestVectors(wycheproof.AeadTestGroup),
	is_xchacha: bool,
	impl: chacha20.Implementation,
) -> bool {
	FLAG_INVALID_NONCE_SIZE :: "InvalidNonceSize"

	alg_str := is_xchacha ? "xchacha20poly1305" : "chacha20poly1305"

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group in test_vectors.test_groups {
		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf(
					"aead/%s/%v/%d: %s: %+v",
					alg_str,
					impl,
					test_vector.tc_id,
					comment,
					test_vector.flags,
				)
			} else {
				log.debugf("aead/%s/%v/%d: %+v",
					alg_str,
					impl,
					test_vector.tc_id,
					test_vector.flags,
				)
			}

			key := wycheproof.hexbytes_decode(test_vector.key)
			iv := wycheproof.hexbytes_decode(test_vector.iv)
			aad := wycheproof.hexbytes_decode(test_vector.aad)
			msg := wycheproof.hexbytes_decode(test_vector.msg)
			ct := wycheproof.hexbytes_decode(test_vector.ct)
			tag := wycheproof.hexbytes_decode(test_vector.tag)

			if slice.contains(test_vector.flags, FLAG_INVALID_NONCE_SIZE) {
				log.infof(
					"aead/%s/%v/%d: skipped, invalid nonces panic",
					alg_str,
					impl,
					test_vector.tc_id,
				)
				num_skipped += 1
				continue
			}

			ctx: chacha20poly1305.Context
			switch is_xchacha {
			case true:
				chacha20poly1305.init_xchacha(&ctx, key, impl)
			case false:
				chacha20poly1305.init(&ctx, key, impl)
			}

			if wycheproof.result_is_valid(test_vector.result) {
				ct_ := make([]byte, len(ct))
				tag_ := make([]byte, len(tag))
				chacha20poly1305.seal(&ctx, ct_, tag_, iv, aad, msg)

				ok := wycheproof.hexbytes_compare(test_vector.ct, ct_)
				if !wycheproof.result_check(test_vector.result, ok) {
					x := transmute(string)(hex.encode(ct_))
					log.errorf(
						"aead/%s/%v/%d: ciphertext: expected %s actual %s",
						alg_str,
						impl,
						test_vector.tc_id,
						test_vector.ct,
						x,
					)
					num_failed += 1
					continue
				}

				ok = wycheproof.hexbytes_compare(test_vector.tag, tag_)
				if !wycheproof.result_check(test_vector.result, ok) {
					x := transmute(string)(hex.encode(tag_))
					log.errorf(
						"aead/%s/%v/%d: tag: expected %s actual %s",
						alg_str,
						impl,
						test_vector.tc_id,
						test_vector.tag,
						x,
					)
					num_failed += 1
					continue
				}
			}

			msg_ := make([]byte, len(msg))
			// ok := chacha20poly1305.decrypt(msg_, tag, key, iv, aad, ct)
			ok := chacha20poly1305.open(&ctx, msg_, iv, aad, ct, tag)
			if !wycheproof.result_check(test_vector.result, ok) {
				log.errorf("aead/%s/%v/%d: decrypt failed",
					alg_str,
					impl,
					test_vector.tc_id,
				)
				num_failed += 1
				continue
			}

			if ok && !wycheproof.hexbytes_compare(test_vector.msg, msg_) {
				x := transmute(string)(hex.encode(msg_))
				log.errorf(
					"aead/%s/%v/%d: decrypt msg: expected %s actual %s",
					alg_str,
					impl,
					test_vector.tc_id,
					test_vector.msg,
					x,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"aead/%s/%v: ran %d, passed %d, failed %d, skipped %d",
		alg_str,
		impl,
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}

test_eddsa_ed25519 :: proc(base_path: string) -> bool {
	fn := filepath.join([]string{base_path, "ed25519_test.json"})

	log.debug("eddsa/ed25519: starting")

	test_vectors: wycheproof.TestVectors(wycheproof.EddsaTestGroup)
	if !wycheproof.load(&test_vectors, fn) {
		return false
	}

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group, i in test_vectors.test_groups {
		pk_bytes := wycheproof.hexbytes_decode(test_group.public_key.pk)

		pk: ed25519.Public_Key
		if !ed25519.public_key_set_bytes(&pk, pk_bytes) {
			log.errorf("eddsa/ed25519/%d: invalid public key: %s", i, test_group.public_key.pk)
			num_failed += len(test_group.tests)
			continue
		}

		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf(
					"eddsa/ed25519/%d: %s: %+v",
					test_vector.tc_id,
					comment,
					test_vector.flags,
				)
			} else {
				log.debugf("eddsa/ed25519/%d: %+v", test_vector.tc_id, test_vector.flags)
			}

			msg := wycheproof.hexbytes_decode(test_vector.msg)
			sig := wycheproof.hexbytes_decode(test_vector.sig)

			ok := ed25519.verify(&pk, msg, sig)
			if !wycheproof.result_check(test_vector.result, ok) {
				log.errorf(
					"eddsa/ed25519/%d: verify failed: expected %s actual %v",
					test_vector.tc_id,
					test_vector.result,
					ok,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"eddsa/ed25519: ran %d, passed %d, failed %d, skipped %d",
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}

test_hkdf :: proc(base_path: string) -> bool {
	files := []string {
		"hkdf_sha1_test.json",
		"hkdf_sha256_test.json",
		"hkdf_sha384_test.json",
		"hkdf_sha512_test.json",
	}

	allOk := true
	for f in files {
		mem.free_all() // Probably don't need this, but be safe.

		fn := filepath.join([]string{base_path, f})

		test_vectors: wycheproof.TestVectors(wycheproof.HkdfTestGroup)
		if !wycheproof.load(&test_vectors, fn) {
			allOk &= false
			continue
		}

		allOk &= test_hkdf_impl(&test_vectors)
	}

	return allOk
}

test_hkdf_impl :: proc(test_vectors: ^wycheproof.TestVectors(wycheproof.HkdfTestGroup)) -> bool {
	PREFIX_HKDF :: "HKDF-"
	FLAG_SIZE_TOO_LARGE :: "SizeTooLarge"

	alg_str := strings.trim_prefix(test_vectors.algorithm, PREFIX_HKDF)
	alg, ok := hash_name_to_algorithm(alg_str)
	if !ok {
		return false
	}
	alg_str = strings.to_lower(alg_str)

	log.debugf("hkdf/%s: starting", alg_str)

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group in test_vectors.test_groups {
		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf(
					"hkdf/%s/%d: %s: %+v",
					alg_str,
					test_vector.tc_id,
					comment,
					test_vector.flags,
				)
			} else {
				log.debugf("hkdf/%s/%d: %+v", alg_str, test_vector.tc_id, test_vector.flags)
			}

			ikm := wycheproof.hexbytes_decode(test_vector.ikm)
			salt := wycheproof.hexbytes_decode(test_vector.salt)
			info := wycheproof.hexbytes_decode(test_vector.info)

			if slice.contains(test_vector.flags, FLAG_SIZE_TOO_LARGE) {
				log.infof(
					"hkdf/%s/%d: skipped, oversized outputs panic",
					alg_str,
					test_vector.tc_id,
				)
				num_skipped += 1
				continue
			}

			okm_ := make([]byte, test_vector.size)
			hkdf.extract_and_expand(alg, salt, ikm, info, okm_)

			ok = wycheproof.hexbytes_compare(test_vector.okm, okm_)
			if !wycheproof.result_check(test_vector.result, ok) {
				x := transmute(string)(hex.encode(okm_))
				log.errorf(
					"hkdf/%s/%d: shared: expected %s actual %s",
					alg_str,
					test_vector.tc_id,
					test_vector.okm,
					x,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"hkdf/%s: ran %d, passed %d, failed %d, skipped %d",
		alg_str,
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}

test_mac :: proc(base_path: string) -> bool {
	files := []string {
		"hmac_sha1_test.json",
		"hmac_sha224_test.json",
		"hmac_sha256_test.json",
		"hmac_sha3_224_test.json",
		"hmac_sha3_256_test.json",
		"hmac_sha3_384_test.json",
		"hmac_sha3_512_test.json",
		"hmac_sha384_test.json",
		// "hmac_sha512_224_test.json",
		"hmac_sha512_256_test.json",
		"hmac_sha512_test.json",
		"hmac_sm3_test.json",
		"kmac128_no_customization_test.json",
		"kmac256_no_customization_test.json",
		"siphash_1_3_test.json",
		"siphash_2_4_test.json",
		"siphash_4_8_test.json",
	}

	allOk := true
	for f in files {
		mem.free_all() // Probably don't need this, but be safe.

		fn := filepath.join([]string{base_path, f})

		test_vectors: wycheproof.TestVectors(wycheproof.MacTestGroup)
		if !wycheproof.load(&test_vectors, fn) {
			allOk &= false
			continue
		}

		allOk &= test_mac_impl(&test_vectors)
	}

	return allOk
}

test_mac_impl :: proc(test_vectors: ^wycheproof.TestVectors(wycheproof.MacTestGroup)) -> bool {
	PREFIX_HMAC :: "HMAC"
	PREFIX_KMAC :: "KMAC"

	mac_alg, hmac_alg, alg_str, ok := mac_algorithm(test_vectors.algorithm)
	if !ok {
		log.errorf("mac: unsupported algorith: %s", test_vectors.algorithm)
		return false
	}

	log.debugf("%s: starting", alg_str)

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group in test_vectors.test_groups {
		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf(
					"%s/%d: %s: %+v",
					alg_str,
					test_vector.tc_id,
					comment,
					test_vector.flags,
				)
			} else {
				log.debugf("%s/%d: %+v", alg_str, test_vector.tc_id, test_vector.flags)
			}

			key := wycheproof.hexbytes_decode(test_vector.key)
			msg := wycheproof.hexbytes_decode(test_vector.msg)

			tag_ := make([]byte, len(test_vector.tag) / 2)

			#partial switch mac_alg {
			case .HMAC:
				ctx: hmac.Context
				hmac.init(&ctx, hmac_alg, key)
				hmac.update(&ctx, msg)
				if l := hmac.tag_size(&ctx); l == len(tag_) {
					hmac.final(&ctx, tag_)
				} else {
					// Our hmac package does not support truncation.
					tmp := make([]byte, l)
					hmac.final(&ctx, tmp)
					copy(tag_, tmp)
				}
			case .KMAC128, .KMAC256:
				ctx: kmac.Context
				#partial switch mac_alg {
				case .KMAC128:
					kmac.init_128(&ctx, key, nil)
				case .KMAC256:
					kmac.init_256(&ctx, key, nil)
				}
				kmac.update(&ctx, msg)
				kmac.final(&ctx, tag_)
			case .SIPHASH_1_3:
				siphash.sum_1_3(msg, key, tag_)
			case .SIPHASH_2_4:
				siphash.sum_2_4(msg, key, tag_)
			case .SIPHASH_4_8:
				siphash.sum_4_8(msg, key, tag_)
			}

			ok = wycheproof.hexbytes_compare(test_vector.tag, tag_)
			if !wycheproof.result_check(test_vector.result, ok) {
				x := transmute(string)(hex.encode(tag_))
				log.errorf(
					"%s/%d: tag: expected %s actual %s",
					alg_str,
					test_vector.tc_id,
					test_vector.tag,
					x,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"%s: ran %d, passed %d, failed %d, skipped %d",
		alg_str,
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}

test_pbkdf2 :: proc(base_path: string) -> bool {
	files := []string {
		"pbkdf2_hmacsha1_test.json",
		"pbkdf2_hmacsha224_test.json",
		"pbkdf2_hmacsha256_test.json",
		"pbkdf2_hmacsha384_test.json",
		"pbkdf2_hmacsha512_test.json",
	}

	allOk := true
	for f in files {
		mem.free_all() // Probably don't need this, but be safe.

		fn := filepath.join([]string{base_path, f})

		test_vectors: wycheproof.TestVectors(wycheproof.PbkdfTestGroup)
		if !wycheproof.load(&test_vectors, fn) {
			allOk &= false
			continue
		}

		allOk &= test_pbkdf2_impl(&test_vectors)
	}

	return allOk
}

test_pbkdf2_impl :: proc(
	test_vectors: ^wycheproof.TestVectors(wycheproof.PbkdfTestGroup),
) -> bool {
	PREFIX_PBKDF_HMAC :: "PBKDF2-HMAC"
	FLAG_LARGE_ITERATION_COUNT :: "LargeIterationCount"

	alg_str := strings.trim_prefix(test_vectors.algorithm, PREFIX_PBKDF_HMAC)
	alg, ok := hash_name_to_algorithm(alg_str)
	if !ok {
		return false
	}
	alg_str = strings.to_lower(alg_str)

	log.debugf("pbkdf2/hmac-%s: starting", alg_str)

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group in test_vectors.test_groups {
		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf(
					"pbkdf2/hmac-%s/%d: %s: %+v",
					alg_str,
					test_vector.tc_id,
					comment,
					test_vector.flags,
				)
			} else {
				log.debugf("pbkdf2/hmac-%s/%d: %+v", alg_str, test_vector.tc_id, test_vector.flags)
			}

			if slice.contains(test_vector.flags, FLAG_LARGE_ITERATION_COUNT) {
				log.infof(
					"pbkdf2/hmac-%s/%d: skipped, takes fucking forever",
					alg_str,
					test_vector.tc_id,
				)
				num_skipped += 1
				continue
			}

			password := wycheproof.hexbytes_decode(test_vector.password)
			salt := wycheproof.hexbytes_decode(test_vector.salt)

			dk_ := make([]byte, test_vector.dk_len)
			pbkdf2.derive(alg, password, salt, test_vector.iteration_count, dk_)

			ok = wycheproof.hexbytes_compare(test_vector.dk, dk_)
			if !wycheproof.result_check(test_vector.result, ok) {
				x := transmute(string)(hex.encode(dk_))
				log.errorf(
					"pbkdf2/hmac-%s/%d: shared: expected %s actual %s",
					alg_str,
					test_vector.tc_id,
					test_vector.dk,
					x,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"pbkdf2/%s: ran %d, passed %d, failed %d, skipped %d",
		alg_str,
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}

test_xdh :: proc(base_path: string) -> bool {
	files := []string {
		"x25519_test.json",
		"x448_test.json",
	}

	allOk := true
	for f in files {
		mem.free_all() // Probably don't need this, but be safe.

		fn := filepath.join([]string{base_path, f})

		test_vectors: wycheproof.TestVectors(wycheproof.XdhTestGroup)
		if !wycheproof.load(&test_vectors, fn) {
			allOk &= false
			continue
		}

		alg_str := strings.trim_suffix(f, SUFFIX_TEST_JSON)
		allOk &= test_xdh_impl(&test_vectors, alg_str)
	}

	return allOk
}

test_xdh_impl :: proc(
	test_vectors: ^wycheproof.TestVectors(wycheproof.XdhTestGroup),
	alg_str: string,
) -> bool {
	ALG_X25519 :: "x25519"
	ALG_X448 :: "x448"

	FLAG_PUBLIC_KEY_TOO_LONG :: "PublicKeyTooLong"

	log.debugf("xdh/%s: starting", alg_str)

	num_ran, num_passed, num_failed, num_skipped: int
	for &test_group in test_vectors.test_groups {
		for &test_vector in test_group.tests {
			num_ran += 1

			if comment := test_vector.comment; comment != "" {
				log.debugf("xdh/%s/%d: %s: %+v", alg_str, test_vector.tc_id, comment, test_vector.flags)
			} else {
				log.debugf("xdh/%s/%d: %+v", alg_str, test_vector.tc_id, test_vector.flags)
			}

			pub := wycheproof.hexbytes_decode(test_vector.public)
			private := wycheproof.hexbytes_decode(test_vector.private)
			shared: []byte

			if slice.contains(test_vector.flags, FLAG_PUBLIC_KEY_TOO_LONG) {
				log.infof(
					"xdh/%s/%d: skipped, invalid sizes panic",
					alg_str,
					test_vector.tc_id,
				)
				num_skipped += 1
				continue
			}

			switch alg_str {
			case ALG_X25519:
				shared = make([]byte, x25519.POINT_SIZE)
				x25519.scalarmult(shared, private, pub)
			case ALG_X448:
				shared = make([]byte, x448.POINT_SIZE)
				x448.scalarmult(shared, private, pub)
			case:
				log.errorf("unsupported algorithm: %s", alg_str)
				return false
			}

			// We have a very forgiving XDH implementation, that
			// intentionally omits the all-zero check, so `acceptable`
			// is treated as valid for the purpose of these tests.
			ok := wycheproof.hexbytes_compare(test_vector.shared, shared)
			if !wycheproof.result_check(test_vector.result, ok, false) {
				x := transmute(string)(hex.encode(shared))
				log.errorf(
					"xdh/%s/%d: shared: expected %s actual %s",
					alg_str,
					test_vector.tc_id,
					test_vector.shared,
					x,
				)
				num_failed += 1
				continue
			}

			num_passed += 1
		}
	}

	assert(num_ran == test_vectors.number_of_tests)
	assert(num_passed + num_failed + num_skipped == num_ran)

	log.infof(
		"xdh/%s: ran %d, passed %d, failed %d, skipped %d",
		alg_str,
		num_ran,
		num_passed,
		num_failed,
		num_skipped,
	)

	return num_failed == 0
}
