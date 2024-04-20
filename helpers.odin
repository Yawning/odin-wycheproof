package main

import "core:crypto/hash"
import "core:log"
import "core:os"

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
