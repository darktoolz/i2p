
isb32=grep -q ".b32.i2p\$$"

test: test-callformat test-type test-base64 test-keytool-domain test-keytool-pxt test-mask

test-callformat:
	keygen /dev/stdout 2>/dev/null | keyinfo /dev/stdin | ${isb32}
	keygen 2>/dev/null | keyinfo | ${isb32}
	keygen - | keyinfo - | ${isb32}
	keygen | keyinfo | ${isb32}

test-base64:
	test "`keygen -x - 0 | base64 -d | keyinfo -t`" = "DSA-SHA1"
	keygen -x - 0 | base64 -d | keyinfo | ${isb32}

test-type:
	test "`keygen -0 | keyinfo -t`" = "DSA-SHA1"
	test "`keygen -1 | keyinfo -t`" = "ECDSA-P256"
	test "`keygen -2 | keyinfo -t`" = "ECDSA-P384"
	test "`keygen -3 | keyinfo -t`" = "ECDSA-P521"
	test "`keygen -4 | keyinfo -t`" = "RSA-2048-SHA256"
	test "`keygen -5 | keyinfo -t`" = "RSA-3072-SHA384"
	test "`keygen -6 | keyinfo -t`" = "RSA-4096-SHA512"
	test "`keygen -7 | keyinfo -t`" = "ED25519-SHA512"
	test "`keygen -9 | keyinfo -t`" = "GOSTR3410-A-GOSTR3411-256"
	test "`keygen -a | keyinfo -t`" = "GOSTR3410-TC26-A-GOSTR3411-512"
	test "`keygen -b | keyinfo -t`" = "RED25519-SHA512"
	test "`keygen - 0 | keyinfo -t`" = "DSA-SHA1"
	test "`keygen - 1 | keyinfo -t`" = "ECDSA-P256"
	test "`keygen - 2 | keyinfo -t`" = "ECDSA-P384"
	test "`keygen - 3 | keyinfo -t`" = "ECDSA-P521"
	test "`keygen - 4 | keyinfo -t`" = "RSA-2048-SHA256"
	test "`keygen - 5 | keyinfo -t`" = "RSA-3072-SHA384"
	test "`keygen - 6 | keyinfo -t`" = "RSA-4096-SHA512"
	test "`keygen - 7 | keyinfo -t`" = "ED25519-SHA512"
	test "`keygen - 9 | keyinfo -t`" = "GOSTR3410-A-GOSTR3411-256"
	test "`keygen - a | keyinfo -t`" = "GOSTR3410-TC26-A-GOSTR3411-512"
	test "`keygen - b | keyinfo -t`" = "RED25519-SHA512"
	test "`keygen - 10 | keyinfo -t`" = "GOSTR3410-TC26-A-GOSTR3411-512"
	test "`keygen - 11 | keyinfo -t`" = "RED25519-SHA512"

test-keytool-pxt:
	test "`keygen -0 | keyinfo -p | base64 -d | keyinfo -t`" = "DSA-SHA1"
	test "`keygen -1 | keyinfo -p | base64 -d | keyinfo -t`" = "ECDSA-P256"
	test "`keygen -2 | keyinfo -p | base64 -d | keyinfo -t`" = "ECDSA-P384"
	test "`keygen -3 | keyinfo -p | base64 -d | keyinfo -t`" = "ECDSA-P521"
	test "`keygen -4 | keyinfo -p | base64 -d | keyinfo -t`" = "RSA-2048-SHA256"
	test "`keygen -5 | keyinfo -p | base64 -d | keyinfo -t`" = "RSA-3072-SHA384"
	test "`keygen -6 | keyinfo -p | base64 -d | keyinfo -t`" = "RSA-4096-SHA512"
	test "`keygen -7 | keyinfo -p | base64 -d | keyinfo -t`" = "ED25519-SHA512"
	test "`keygen -9 | keyinfo -p | base64 -d | keyinfo -t`" = "GOSTR3410-A-GOSTR3411-256"
	test "`keygen -a | keyinfo -p | base64 -d | keyinfo -t`" = "GOSTR3410-TC26-A-GOSTR3411-512"
	test "`keygen -b | keyinfo -p | base64 -d | keyinfo -t`" = "RED25519-SHA512"
	test "`keygen - 0 | keyinfo -p | base64 -d | keyinfo -t`" = "DSA-SHA1"
	test "`keygen - 1 | keyinfo -p | base64 -d | keyinfo -t`" = "ECDSA-P256"
	test "`keygen - 2 | keyinfo -p | base64 -d | keyinfo -t`" = "ECDSA-P384"
	test "`keygen - 3 | keyinfo -p | base64 -d | keyinfo -t`" = "ECDSA-P521"
	test "`keygen - 4 | keyinfo -p | base64 -d | keyinfo -t`" = "RSA-2048-SHA256"
	test "`keygen - 5 | keyinfo -p | base64 -d | keyinfo -t`" = "RSA-3072-SHA384"
	test "`keygen - 6 | keyinfo -p | base64 -d | keyinfo -t`" = "RSA-4096-SHA512"
	test "`keygen - 7 | keyinfo -p | base64 -d | keyinfo -t`" = "ED25519-SHA512"
	test "`keygen - 9 | keyinfo -p | base64 -d | keyinfo -t`" = "GOSTR3410-A-GOSTR3411-256"
	test "`keygen - a | keyinfo -p | base64 -d | keyinfo -t`" = "GOSTR3410-TC26-A-GOSTR3411-512"
	test "`keygen - b | keyinfo -p | base64 -d | keyinfo -t`" = "RED25519-SHA512"
	test "`keygen - 10 | keyinfo -p | base64 -d | keyinfo -t`" = "GOSTR3410-TC26-A-GOSTR3411-512"
	test "`keygen - 11 | keyinfo -p | base64 -d | keyinfo -t`" = "RED25519-SHA512"

test-keytool-domain:
	for i in `seq 0 9` a b; do \
		keygen -$$i | keyinfo -d | ${isb32}; \
		keygen - $$i | keyinfo -d | ${isb32}; \
	done;
	keygen - 10 | keyinfo -d | ${isb32}
	keygen - 11 | keyinfo -d | ${isb32}

test-mask:
	keygen -xm ne | grep -q "^ne"

.PHONY: test
