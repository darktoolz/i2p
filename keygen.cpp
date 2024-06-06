#define KEYGEN

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <unistd.h>
#include "Crypto.h"
#include "Identity.h"
#include "common/key.hpp"

#include <stdio.h>
#include <string>
#include <vector>
#include <time.h>
#include "I2PEndian.h"
#include "LeaseSet.h"

#define BUFFER_LEN 8192

i2p::data::SigningKeyType default_type = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;

#ifdef NOTHING
// this code is kept here in case of future changes in i2pd Base64 functions
// Base64 encoding has non-standard table in i2pd
/*
--- 
+++ i2pd/libi2pd/Base.cpp 1970-00-01 00:00:00.000000000 +0000
@@ -47,7 +47,7 @@
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
-   '4', '5', '6', '7', '8', '9', '-', '~'
+   '4', '5', '6', '7', '8', '9', '+', '/'
  };

  const char * GetBase64SubstitutionTable ()
*/
// from i2p::data::ToBase64Standard
std::string ToBase64Standard(const std::string& in) {
	auto l = in.length();
	char * str = new char[l + 1];
	str[l]=0;
	const char * instr = in.c_str();
	for (size_t i = 0; i < l; i++) {
		if (instr[i] == '-') { str[i] = '+'; }
		else if (instr[i] == '~') { str[i] = '/'; }
		else { str[i] = instr[i]; }}
	std::string s(str);
	delete[] str;
	return s;
}
#else
//std::string ToBase64Standard(const std::string& in) { return in; }
#define ToBase64Standard(x) x
#endif

std::string achar("a");
std::string bchar("b");
std::string dev_stdout("/dev/stdout");
std::string dev_stdin("/dev/stdin");
std::string minus("-");

struct options {
	bool domain;
	bool type;
	bool priv;

	bool verbose;
	bool base64;
  bool mask;
	int itype;
	int found;
	std::string path;
	std::string ttype;
};
struct options opt = {
	false,
	false,
	false,
	false,
	false,
  false,
	int(default_type),
	0,
	"",
	""
};
uint16_t SigType(const std::string & keyname) {
	if (keyname == achar) return i2p::data::SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512;
	if (keyname == bchar) return i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519;
	if(keyname.find("RED25519") != std::string::npos) return i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519;
	return NameToSigType(keyname);
}
std::string ConvertTime (time_t t)
{
  struct tm *tm = localtime(&t);
  char date[128];
  snprintf(date, sizeof(date), "%02d/%02d/%d %02d:%02d:%02d", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
  return date;
}

static int printHelp(const char * exe, int exitcode) {
#ifdef KEYGEN
  std::cout << "usage: " << exe << " [-h] [-v] [-x] [-m] [-X] [keyout/mask] [keytype]" << std::endl;
	std::cout << "  [keyout]:  key output path (\"-\" or \"/dev/stdin\" accepted), default: empty (equal to \"-\")" << std::endl;
	std::cout << "  [keytype]: default: ED25519-SHA512" << std::endl;
	std::cout << "  -x: base64" << std::endl;
	std::cout << "  -m: use mask: create keys till find one starting from mask (out to stdout)" << std::endl;
	std::cout << "  -X: key id: X == [0, 1, 2, 3, 4, 5, 6, 7, 9, a, b]" << std::endl;
	std::cout << "    id: type" << std::endl;
	std::cout << "    -0: DSA-SHA1" << std::endl;
	std::cout << "    -1: ECDSA-P256 (aka ECDSA-SHA256-P256)" << std::endl;
	std::cout << "    -2: ECDSA-P384 (aka ECDSA-SHA384-P384)" << std::endl;
	std::cout << "    -3: ECDSA-P521 (aka ECDSA-SHA512-P521)" << std::endl;
	std::cout << "    -4: RSA-2048-SHA256 (aka RSA-SHA256-2048)" << std::endl;
	std::cout << "    -5: RSA-3072-SHA384 (aka RSA-SHA384-3072)" << std::endl;
	std::cout << "    -6: RSA-4096-SHA512 (aka RSA-SHA512-4096)" << std::endl;
	std::cout << "    -7: ED25519-SHA512 (aka EDDSA-SHA512-ED25519) (default)" << std::endl;
	std::cout << "    -9: GOSTR3410-A-GOSTR3411-256 (aka GOSTR3410_CRYPTO_PRO_A-GOSTR3411-256)" << std::endl;
	std::cout << "    -a: GOSTR3410-TC26-A-GOSTR3411-512 (aka GOSTR3410_TC26_A_512-GOSTR3411-512)" << std::endl;
	std::cout << "    -b: RED25519-SHA512" << std::endl;
#else
  std::cout << "usage: " << exe << " [-h] [-v] [-d] [-t] [-p] [keyin]" << std::endl;
	std::cout << "  [keyin]:  key input path (\"-\" or \"/dev/stdin\" accepted), default: empty (equal to \"-\")" << std::endl;
	std::cout << "  -d: domain (default action without parameters)" << std::endl;
	std::cout << "  -t: type" << std::endl;
	std::cout << "  -p: private key in hex" << std::endl;
#endif
  std::cout << "  -h: help" << std::endl;
  std::cout << "  -v: verbose" << std::endl;

  return exitcode;
}

static std::ostream* open_out(std::string path) {
	return new std::ofstream(path, std::ofstream::binary | std::ofstream::out);
}
static std::istream* open_in(std::string path) {
	return new std::ifstream(path, std::ofstream::binary | std::ifstream::in);
}

struct options* redirect_cout(struct options* opt) {
	if (!opt->mask && opt->path.size() && (opt->path != dev_stdout && opt->path!=minus)) {
		std::ostream* f = open_out(opt->path);
		if (!f || !f->good()) { if (opt->verbose) std::cerr << "error: file.open(" << opt->path << ")" <<  std::endl; return NULL; }
		std::cout.rdbuf(f->rdbuf());
	}
	return opt;
}

struct options* redirect_cin(struct options* opt) {
	if (opt->path.size() && (opt->path != dev_stdin && opt->path!=minus)) {
		std::istream* f = open_in(opt->path);
		if (!f || !f->good()) { if (opt->verbose) std::cerr << "error: file.open(" << opt->path << ")" <<  std::endl; return NULL; }
		std::cin.rdbuf(f->rdbuf());
	}
	return opt;
}

int keygen(struct options* opt) {
  if (!opt) return -1;
  i2p::crypto::InitCrypto (false, true, false);
	if (opt->ttype.size()) opt->itype = SigType(opt->ttype);
	i2p::data::SigningKeyType type = i2p::data::SigningKeyType(opt->itype);
	if (SigTypeToName(type).find("unknown") != std::string::npos) { if (opt->verbose) std::cerr << "Incorrect signature type: " << type << std::endl; return -2; }
  auto keys = i2p::data::PrivateKeys::CreateRandomKeys(type);
  int counter = 0;
  if (opt->mask && opt->path != "") {
    if (opt->verbose) std::cerr << "Generating key using mask: '" << opt->path << std::endl;
    while (ToBase64Standard(keys.ToBase64()).find(opt->path.c_str()) != 0) {
      if (opt->verbose && counter % 2048 == 0) { std::cout << "Checked " << counter << " keys" << std::endl; }
      keys = i2p::data::PrivateKeys::CreateRandomKeys (type);
      counter++;
    }
  }
  if (opt->base64) {
		std::cout << ToBase64Standard(keys.ToBase64()) << std::endl;
  } else {
		size_t len = BUFFER_LEN;
    uint8_t * buf = new uint8_t[len];
    len = keys.ToBuffer (buf, len);
    std::cout.write((char *)buf, len);
    delete[] buf;
  }
  i2p::crypto::TerminateCrypto ();
  return 0;
}

int keyinfo(struct options* opt) {
	if (!opt) return -1;

	if (!opt->type && !opt->priv)
		opt->domain = true;

	i2p::data::PrivateKeys keys;

  size_t len = BUFFER_LEN;
  uint8_t * buf = new uint8_t[len];
  std::cin.read((char*)buf, len);

  if (!keys.FromBuffer(buf, len)) {
    if (opt->verbose) std::cerr << "bad key file format" << std::endl;
    return 3;
  }
	auto dest = keys.GetPublic();
  if(!dest) {
    if (opt->verbose) std::cerr << "failed to extract public key" << std::endl;
    return 3;
  }

	if (opt->type) {
		if (opt->verbose) std::cout << "Signature Type: ";
		std::cout << SigTypeToName(dest->GetSigningKeyType()) << std::endl;
	}
	if (opt->priv) {
		if (opt->verbose) std::cout << "Private Key: ";
		std::cout << ToBase64Standard(keys.ToBase64()) << std::endl;
	}
	if (opt->domain) {
		const auto & ident = dest->GetIdentHash();
		if (opt->verbose) std::cout << "B32 Address: ";
		std::cout << ident.ToBase32() << ".b32.i2p" << std::endl;
	}

	return 0;
}

int main (int argc, char * argv[]) {
	int option = 0;
#ifdef KEYGEN
  while((option = getopt(argc, argv, "hvabxm0123456789")) != -1) {
#else
  while((option = getopt(argc, argv, "hvptd")) != -1) {
#endif
		opt.found++;
    switch(option){
    case 'h':
      return printHelp(argv[0], 0);
    case 'v':
      opt.verbose = true;
      break;
#ifndef KEYGEN
    case 'p':
      opt.priv = true;
      break;
    case 't':
      opt.type = true;
      break;
    case 'd':
      opt.domain = true;
      break;
    default:
			return printHelp(argv[0], -1);
			break;
#else
    case 'm':
      opt.mask = true;
      break;
    case 'x':
      opt.base64 = true;
      break;
    case 'b':
			opt.itype = 11;
      break;
		case 'a':
			opt.itype = 10;
			break;
    default:
			if ('0'<=option and option<='9') { opt.itype = option-'0'; }
			else { return printHelp(argv[0], -1); }
			break;
#endif
    }
  }
	if (optind != argc) { opt.path = argv[optind++]; }
	if (optind != argc) { opt.ttype = argv[optind++]; }
	if (optind != argc) { return printHelp(argv[0], -1); }

#ifdef KEYGEN
	return keygen(redirect_cout(&opt));
#else
	return keyinfo(redirect_cin(&opt));
#endif
  return 0;
}
