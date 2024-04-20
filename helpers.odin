package main

import "core:crypto/hash"
import "core:fmt"
import "core:log"
import "core:os"
import "core:strings"

env_to_log_level :: proc() -> log.Level {
	switch s := os.get_env("ODIN_LOG"); s {
	case "debug":
		return .Debug
	case "info":
		return .Info
	case "warn", "warning":
		return .Warning
	case "error":
		return .Error
	case "fatal":
		return .Fatal
	}
	return .Info
}

hash_name_to_algorithm :: proc(alg_str: string) -> (hash.Algorithm, bool) {
	alg_enums := [][hash.Algorithm]string {
		hash.ALGORITHM_NAMES,
		// The HMAC test vectors omit `-`.
		#partial [hash.Algorithm]string {
			.SHA224 = "SHA224",
			.SHA256 = "SHA256",
			.SHA384 = "SHA384",
			.SHA512 = "SHA512",
			.SHA512_256 = "SHA512/256",
			.Insecure_SHA1 = "SHA1",
		},
	}
	for &e in alg_enums {
		for n, alg in e {
			if n == alg_str {
				return alg, true
			}
		}
	}

	return .Invalid, false
}

MAC_ALGORITHM :: enum {
	Invalid,
	HMAC,
	KMAC128,
	KMAC256,
}

mac_algorithm :: proc(alg_str: string) -> (MAC_ALGORITHM, hash.Algorithm, string, bool) {
	PREFIX_HMAC :: "HMAC"
	KMAC128 :: "KMAC128"
	KMAC256 :: "KMAC256"

	switch {
	case strings.has_prefix(alg_str, PREFIX_HMAC):
		alg_str_ := strings.trim_prefix(alg_str, PREFIX_HMAC)
		alg, ok := hash_name_to_algorithm(alg_str_)
		alg_str_ = fmt.aprintf("hmac/%s", strings.to_lower(alg_str_))
		return .HMAC, alg, alg_str_, ok
	case alg_str == KMAC128:
		return .KMAC128, .Invalid, "kmac128", true
	case alg_str == KMAC256:
		return .KMAC256, .Invalid, "kmac256", true
	}
	return .Invalid, .Invalid, alg_str, false
}
