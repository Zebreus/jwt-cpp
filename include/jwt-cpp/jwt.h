#ifndef JWT_CPP_JWT_H
#define JWT_CPP_JWT_H

#ifndef DISABLE_PICOJSON
#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include "picojson/picojson.h"
#endif

#ifndef DISABLE_BASE64
#include "base.h"
#endif

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#include <chrono>
#include <memory>
#include <set>
#include <unordered_map>
#include <utility>
#include <functional>

#ifdef __cpp_lib_void_t
// We have std::void_t and std::make_void
#include <type_traits>
#endif

//If openssl version less than 1.1
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OPENSSL10
#endif

#ifndef JWT_CLAIM_EXPLICIT
#define JWT_CLAIM_EXPLICIT explicit
#endif

/**
 * \brief JSON Web Token
 * 
 * A namespace to contain everything related to handling JSON Web Tokens, JWT for short,
 * as a part of [RFC7519](https://tools.ietf.org/html/rfc7519), or alternatively for
 * JWS (JSON Web Signature)from [RFC7515](https://tools.ietf.org/html/rfc7515)
 */ 
namespace jwt {
	using date = std::chrono::system_clock::time_point;

	struct signature_verification_exception : public std::runtime_error {
		signature_verification_exception()
			: std::runtime_error("signature verification failed")
		{}
		explicit signature_verification_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit signature_verification_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct signature_generation_exception : public std::runtime_error {
		signature_generation_exception()
			: std::runtime_error("signature generation failed")
		{}
		explicit signature_generation_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit signature_generation_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct rsa_exception : public std::runtime_error {
		explicit rsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit rsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct ecdsa_exception : public std::runtime_error {
		explicit ecdsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit ecdsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct token_verification_exception : public std::runtime_error {
		token_verification_exception()
			: std::runtime_error("token verification failed")
		{}
		explicit token_verification_exception(const std::string& msg)
			: std::runtime_error("token verification failed: " + msg)
		{}
	};

	/**
	 * \brief A collection for working with certificates
	 * 
	 * These _helpers_ are usefully when working with certificates OpenSSL APIs.
	 * For example, when dealing with JWKS (JSON Web Key Set)[https://tools.ietf.org/html/rfc7517]
	 * you maybe need to extract the modulus and exponent of an RSA Public Key.
	 */ 
	namespace helper {
		inline
		std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw = "") {
#if OPENSSL_VERSION_NUMBER <= 0x10100003L
			std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(const_cast<char*>(certstr.data()), certstr.size()), BIO_free_all);
#else
			std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(certstr.data(), static_cast<int>(certstr.size())), BIO_free_all);
#endif
			std::unique_ptr<BIO, decltype(&BIO_free_all)> keybio(BIO_new(BIO_s_mem()), BIO_free_all);

			std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);
			if (!cert) throw rsa_exception("Error loading cert into memory");
			std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
			if(!key) throw rsa_exception("Error getting public key from certificate");
			if(PEM_write_bio_PUBKEY(keybio.get(), key.get()) == 0) throw rsa_exception("Error writing public key data in PEM format");
			char* ptr = nullptr;
			auto len = BIO_get_mem_data(keybio.get(), &ptr);
			if(len <= 0 || ptr == nullptr) throw rsa_exception("Failed to convert pubkey to pem");
			std::string res(ptr, len);
			return res;
		}

		inline
		std::shared_ptr<EVP_PKEY> load_public_key_from_string(const std::string& key, const std::string& password = "") {
			std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
			if(key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
				auto epkey = helper::extract_pubkey_from_cert(key, password);
				const int len = static_cast<int>(epkey.size());
				if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len)
					throw rsa_exception("failed to load public key: bio_write failed");
			} else {
				const int len = static_cast<int>(key.size());
				if (BIO_write(pubkey_bio.get(), key.data(), len) != len)
					throw rsa_exception("failed to load public key: bio_write failed");
			}
			
			std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)password.data()), EVP_PKEY_free);  // NOLINT(google-readability-casting) requires `const_cast`
			if (!pkey)
				throw rsa_exception("failed to load public key: PEM_read_bio_PUBKEY failed:" + std::string(ERR_error_string(ERR_get_error(), nullptr)));
			return pkey;
		}

		inline
		std::shared_ptr<EVP_PKEY> load_private_key_from_string(const std::string& key, const std::string& password = "") {
			std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
			const int len = static_cast<int>(key.size());
			if (BIO_write(privkey_bio.get(), key.data(), len) != len)
				throw rsa_exception("failed to load private key: bio_write failed");
			std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())), EVP_PKEY_free);
			if (!pkey)
				throw rsa_exception("failed to load private key: PEM_read_bio_PrivateKey failed");
			return pkey;
		}
		
		/**
		 * Convert a OpenSSL BIGNUM to a std::string
		 * \param bn BIGNUM to convert
		 * \return bignum as string
		 */
		inline
#ifdef OPENSSL10
		static std::string bn2raw(BIGNUM* bn)
#else
		static std::string bn2raw(const BIGNUM* bn)
#endif
		{
			std::string res;
			res.resize(BN_num_bytes(bn));
			BN_bn2bin(bn, (unsigned char*)res.data());  // NOLINT(google-readability-casting) requires `const_cast`
			return res;
		}
		/**
		 * Convert an std::string to a OpenSSL BIGNUM
		 * \param raw String to convert
		 * \return BIGNUM representation
		 */
		inline
		static std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(const std::string& raw) {
			return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()), static_cast<int>(raw.size()), nullptr), BN_free);
		}
	}  // namespace helper

	/**
	 * \brief Various cryptographic algorithms when working with JWT
	 * 
	 * JWT (JSON Web Tokens) signatures are typically used as the payload for a JWS (JSON Web Signature) or
	 * JWE (JSON Web Encryption). Both of these use various cryptographic as specified by [RFC7518](https://tools.ietf.org/html/rfc7518)
	 * and are exposed through the a [JOSE Header](https://tools.ietf.org/html/rfc7515#section-4) which 
	 * points to one of the JWA (JSON Web Algorithms)(https://tools.ietf.org/html/rfc7518#section-3.1)
	 */
	namespace algorithm {
		/**
		 * \brief "none" algorithm.
		 * 
		 * Returns and empty signature and checks if the given signature is empty.
		 */
		struct none {
			/**
			 * \brief Return an empty string
			 */ 
			std::string sign(const std::string& /*unused*/) const {
				return "";
			}
			/**
			 * \brief Check if the given signature is empty.
			 * 
			 * JWT's with "none" algorithm should not contain a signature.
			 * \throw signature_verification_exception
			 */ 
			void verify(const std::string& /*unused*/, const std::string& signature) const {
				if (!signature.empty())
					throw signature_verification_exception();
			}
			/// Get algorithm name
			std::string name() const {
				return "none";
			}
		};
		/**
		 * \brief Base class for HMAC family of algorithms
		 */
		struct hmacsha {
			/**
			 * Construct new hmac algorithm
			 * \param key Key to use for HMAC
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			hmacsha(std::string key, const EVP_MD*(*md)(), std::string  name)
				: secret(std::move(key)), md(md), alg_name(std::move(name))
			{}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return HMAC signature for the given data
			 * \throw signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				std::string res;
				res.resize(static_cast<size_t>(EVP_MAX_MD_SIZE));
				auto len = static_cast<unsigned int>(res.size());
				if (HMAC(md(), secret.data(), static_cast<int>(secret.size()), reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size()), (unsigned char*)res.data(), &len) == nullptr)  // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception();
				res.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				try {
					auto res = sign(data);
					bool matched = true;
					for (size_t i = 0; i < std::min<size_t>(res.size(), signature.size()); i++)
						if (res[i] != signature[i])
							matched = false;
					if (res.size() != signature.size())
						matched = false;
					if (!matched)
						throw signature_verification_exception();
				}
				catch (const signature_generation_exception&) {
					throw signature_verification_exception();
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/// HMAC secrect
			const std::string secret;
			/// HMAC hash generator
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
		};
		/**
		 * \brief Base class for RSA family of algorithms
		 */
		struct rsa {
			/**
			 * Construct new rsa algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			rsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), std::string  name)
				: md(md), alg_name(std::move(name))
			{
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if(!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw rsa_exception("at least one of public or private key need to be present");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return RSA signature for the given data
			 * \throw signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx)
					throw signature_generation_exception("failed to create signature: could not create context");
				if (!EVP_SignInit(ctx.get(), md()))
					throw signature_generation_exception("failed to create signature: SignInit failed");

				std::string res;
				res.resize(EVP_PKEY_size(pkey.get()));
				unsigned int len = 0;

				if (!EVP_SignUpdate(ctx.get(), data.data(), data.size()))
					throw signature_generation_exception();
				if (EVP_SignFinal(ctx.get(), (unsigned char*)res.data(), &len, pkey.get()) == 0)   // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception();

				res.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx)
					throw signature_verification_exception("failed to verify signature: could not create context");
				if (!EVP_VerifyInit(ctx.get(), md()))
					throw signature_verification_exception("failed to verify signature: VerifyInit failed");
				if (!EVP_VerifyUpdate(ctx.get(), data.data(), data.size()))
					throw signature_verification_exception("failed to verify signature: VerifyUpdate failed");
				auto res = EVP_VerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()), static_cast<unsigned int>(signature.size()), pkey.get());
				if (res != 1)
					throw signature_verification_exception("evp verify final failed: " + std::to_string(res) + " " + ERR_error_string(ERR_get_error(), nullptr));
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/// OpenSSL structure containing converted keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
		};
		/**
		 * \brief Base class for ECDSA family of algorithms
		 */
		struct ecdsa {
			/**
			 * Construct new ecdsa algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			ecdsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), std::string  name, size_t siglen)
				: md(md), alg_name(std::move(name)), signature_length(siglen)
			{
				if (!public_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if(public_key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
						auto epkey = helper::extract_pubkey_from_cert(public_key, public_key_password);
						const int len = static_cast<int>(epkey.size());
						if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len)
							throw ecdsa_exception("failed to load public key: bio_write failed");
					} else  {
						const int len = static_cast<int>(public_key.size());
						if (BIO_write(pubkey_bio.get(), public_key.data(), len) != len)
							throw ecdsa_exception("failed to load public key: bio_write failed");
					}

					pkey.reset(PEM_read_bio_EC_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()), EC_KEY_free);  // NOLINT(google-readability-casting) requires `const_cast`
					if (!pkey)
						throw ecdsa_exception("failed to load public key: PEM_read_bio_EC_PUBKEY failed:" + std::string(ERR_error_string(ERR_get_error(), nullptr)));
					size_t keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
					if(keysize != signature_length*4 && (signature_length != 132 || keysize != 521))
						throw ecdsa_exception("invalid key size");
				}

				if (!private_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						const int len = static_cast<int>(private_key.size());
					if (BIO_write(privkey_bio.get(), private_key.data(), len) != len)
						throw ecdsa_exception("failed to load private key: bio_write failed");
					pkey.reset(PEM_read_bio_ECPrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(private_key_password.c_str())), EC_KEY_free);
					if (!pkey)
						throw ecdsa_exception("failed to load private key: PEM_read_bio_ECPrivateKey failed");
					size_t keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
					if(keysize != signature_length*4 && (signature_length != 132 || keysize != 521))
						throw ecdsa_exception("invalid key size");
				}
				if(!pkey)
					throw ecdsa_exception("at least one of public or private key need to be present");

				if(EC_KEY_check_key(pkey.get()) == 0)
					throw ecdsa_exception("failed to load key: key is invalid");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return ECDSA signature for the given data
			 * \throw signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				const std::string hash = generate_hash(data);

				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>
					sig(ECDSA_do_sign(reinterpret_cast<const unsigned char*>(hash.data()), static_cast<int>(hash.size()), pkey.get()), ECDSA_SIG_free);
				if(!sig)
					throw signature_generation_exception();
#ifdef OPENSSL10

				auto rr = helper::bn2raw(sig->r);
				auto rs = helper::bn2raw(sig->s);
#else
				const BIGNUM *r;
				const BIGNUM *s;
				ECDSA_SIG_get0(sig.get(), &r, &s);
				auto rr = helper::bn2raw(r);
				auto rs = helper::bn2raw(s);
#endif
				if(rr.size() > signature_length/2 || rs.size() > signature_length/2)
					throw std::logic_error("bignum size exceeded expected length");
				rr.insert(0, signature_length/2 - rr.size(), '\0');
				rs.insert(0, signature_length/2 - rs.size(), '\0');
				return rr + rs;
			}

			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				const std::string hash = generate_hash(data);
				auto r = helper::raw2bn(signature.substr(0, signature.size() / 2));
				auto s = helper::raw2bn(signature.substr(signature.size() / 2));

#ifdef OPENSSL10
				ECDSA_SIG sig;
				sig.r = r.get();
				sig.s = s.get();

				if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), &sig, pkey.get()) != 1)
					throw signature_verification_exception("Invalid signature");
#else
				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_new(), ECDSA_SIG_free);

				ECDSA_SIG_set0(sig.get(), r.release(), s.release());

				if(ECDSA_do_verify(reinterpret_cast<const unsigned char*>(hash.data()), static_cast<int>(hash.size()), sig.get(), pkey.get()) != 1)
					throw signature_verification_exception("Invalid signature");
#endif
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \return Hash of data
			 */
			std::string generate_hash(const std::string& data) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
				if(EVP_DigestInit(ctx.get(), md()) == 0)
					throw signature_generation_exception("EVP_DigestInit failed");
				if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0)
					throw signature_generation_exception("EVP_DigestUpdate failed");
				unsigned int len = 0;
				std::string res;
				res.resize(EVP_MD_CTX_size(ctx.get()));
				if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("EVP_DigestFinal failed");
				res.resize(len);
				return res;
			}

			/// OpenSSL struct containing keys
			std::shared_ptr<EC_KEY> pkey;
			/// Hash generator function
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
			/// Length of the resulting signature
			const size_t signature_length;
		};

		/**
		 * \brief Base class for PSS-RSA family of algorithms
		 */
		struct pss {
			/**
			 * Construct new pss algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			pss(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), std::string  name)
				: md(md), alg_name(std::move(name))
			{
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if(!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw rsa_exception("at least one of public or private key need to be present");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return ECDSA signature for the given data
			 * \throw signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				auto hash = this->generate_hash(data);

				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				const int size = RSA_size(key.get());

				std::string padded(size, 0x00);
				if (RSA_padding_add_PKCS1_PSS_mgf1(key.get(), (unsigned char*)padded.data(), reinterpret_cast<const unsigned char*>(hash.data()), md(), md(), -1) == 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("failed to create signature: RSA_padding_add_PKCS1_PSS_mgf1 failed");

				std::string res(size, 0x00);
				if (RSA_private_encrypt(size, reinterpret_cast<const unsigned char*>(padded.data()), (unsigned char*)res.data(), key.get(), RSA_NO_PADDING) < 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("failed to create signature: RSA_private_encrypt failed");
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				auto hash = this->generate_hash(data);

				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				const int size = RSA_size(key.get());
				
				std::string sig(size, 0x00);
				if(RSA_public_decrypt(static_cast<int>(signature.size()), reinterpret_cast<const unsigned char*>(signature.data()), (unsigned char*)sig.data(), key.get(), RSA_NO_PADDING) == 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_verification_exception("Invalid signature");
				
				if(RSA_verify_PKCS1_PSS_mgf1(key.get(), reinterpret_cast<const unsigned char*>(hash.data()), md(), md(), reinterpret_cast<const unsigned char*>(sig.data()), -1) == 0)
					throw signature_verification_exception("Invalid signature");
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \return Hash of data
			 */
			std::string generate_hash(const std::string& data) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
				if(EVP_DigestInit(ctx.get(), md()) == 0)
					throw signature_generation_exception("EVP_DigestInit failed");
				if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0)
					throw signature_generation_exception("EVP_DigestUpdate failed");
				unsigned int len = 0;
				std::string res;
				res.resize(EVP_MD_CTX_size(ctx.get()));
				if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("EVP_DigestFinal failed");
				res.resize(len);
				return res;
			}
			
			/// OpenSSL structure containing keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator function
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
		};

		/**
		 * HS256 algorithm
		 */
		struct hs256 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs256(std::string key)
				: hmacsha(std::move(key), EVP_sha256, "HS256")
			{}
		};
		/**
		 * HS384 algorithm
		 */
		struct hs384 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs384(std::string key)
				: hmacsha(std::move(key), EVP_sha384, "HS384")
			{}
		};
		/**
		 * HS512 algorithm
		 */
		struct hs512 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs512(std::string key)
				: hmacsha(std::move(key), EVP_sha512, "HS512")
			{}
		};
		/**
		 * RS256 algorithm
		 */
		struct rs256 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit rs256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256")
			{}
		};
		/**
		 * RS384 algorithm
		 */
		struct rs384 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit rs384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384")
			{}
		};
		/**
		 * RS512 algorithm
		 */
		struct rs512 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit rs512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512")
			{}
		};
		/**
		 * ES256 algorithm
		 */
		struct es256 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit es256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256", 64)
			{}
		};
		/**
		 * ES384 algorithm
		 */
		struct es384 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit es384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384", 96)
			{}
		};
		/**
		 * ES512 algorithm
		 */
		struct es512 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit es512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512", 132)
			{}
		};

		/**
		 * PS256 algorithm
		 */
		struct ps256 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit ps256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256")
			{}
		};
		/**
		 * PS384 algorithm
		 */
		struct ps384 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit ps384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384")
			{}
		};
		/**
		 * PS512 algorithm
		 */
		struct ps512 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit ps512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512")
			{}
		};
	}  // namespace algorithm

	/**
	 * \brief JSON Abstractions for working with any library
	 */ 
	namespace json {
		/**
		 * \brief Generic JSON types used in JWTs
		 * 
		 * This enum is to abstract the third party underlying types
		 */
		enum class type {
			boolean,
			integer,
			number,
			string,
			array,
			object
		};
	}  // namespace json

	namespace details {
		namespace impl {

#ifdef __cpp_lib_void_t
		template <typename... Ts>
		using void_t = std::void_t<Ts...>;
#else
		// https://en.cppreference.com/w/cpp/types/void_t
		template <typename ...Ts>
		struct make_void
		{
			using type = void;
		};

		template <typename ...Ts>
		using void_t = typename make_void<Ts...>::type;
#endif
		struct nonesuch
		{
			nonesuch() = delete;
			~nonesuch() = delete;
			nonesuch(nonesuch const&) = delete;
			nonesuch(nonesuch const&&) = delete;
			void operator=(nonesuch const&) = delete;
			void operator=(nonesuch&&) = delete;
		};

		// https://en.cppreference.com/w/cpp/experimental/is_detected
		template <class Default, class AlwaysVoid, template <class...> class Op, class... Args>
		struct detector
		{
			using value = std::false_type;
			using type = Default;
		};

		template <class Default, template <class...> class Op, class... Args>
		struct detector<Default, void_t<Op<Args...>>, Op, Args...>
		{
			using value = std::true_type;
			using type = Op<Args...>;
		};
		}  // namespace impl

		template <template <class...> class Op, class... Args>
		using is_detected = typename impl::detector<impl::nonesuch, void, Op, Args...>::value;

		template <template <class...> class Op, class... Args>
		using is_detected_t = typename impl::detector<impl::nonesuch, void, Op, Args...>::type;

		template <typename traits_type>
		using get_type_function = decltype(traits_type::get_type);

		template <typename traits_type, typename value_type>
		using is_get_type_signature = typename std::is_same<get_type_function<traits_type>, json::type(const value_type&)>;

		template <typename traits_type, typename value_type>
		struct supports_get_type {
			static constexpr auto value =
				is_detected<get_type_function, traits_type>::value && 
				std::is_function<get_type_function<traits_type>>::value &&
				is_get_type_signature<traits_type, value_type>::value;
		};

		template <typename traits_type>
		using as_object_function = decltype(traits_type::as_object);

		template <typename traits_type, typename value_type, typename object_type>
		using is_as_object_signature = typename std::is_same<as_object_function<traits_type>, object_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename object_type>
		struct supports_as_object {
			static constexpr auto value =
			    std::is_constructible<value_type, object_type>::value &&
				is_detected<as_object_function, traits_type>::value &&
				std::is_function<as_object_function<traits_type>>::value &&
				is_as_object_signature<traits_type, value_type, object_type>::value;
		};

		template <typename traits_type>
		using as_array_function = decltype(traits_type::as_array);

		template <typename traits_type, typename value_type, typename array_type>
		using is_as_array_signature = typename std::is_same<as_array_function<traits_type>, array_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename array_type>
		struct supports_as_array {
			static constexpr auto value =
			    std::is_constructible<value_type, array_type>::value &&
				is_detected<as_array_function, traits_type>::value &&
				std::is_function<as_array_function<traits_type>>::value &&
				is_as_array_signature<traits_type, value_type, array_type>::value;
		};

		template <typename traits_type>
		using as_string_function = decltype(traits_type::as_string);

		template <typename traits_type, typename value_type, typename string_type>
		using is_as_string_signature = typename std::is_same<as_string_function<traits_type>, string_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename string_type>
		struct supports_as_string {
			static constexpr auto value =
			    std::is_constructible<value_type, string_type>::value &&
				is_detected<as_string_function, traits_type>::value &&
				std::is_function<as_string_function<traits_type>>::value &&
				is_as_string_signature<traits_type, value_type, string_type>::value;
		};

		template <typename traits_type>
		using as_number_function = decltype(traits_type::as_number);

		template <typename traits_type, typename value_type, typename number_type>
		using is_as_number_signature = typename std::is_same<as_number_function<traits_type>, number_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename number_type>
		struct supports_as_number {
			static constexpr auto value =
				std::is_floating_point<number_type>::value &&
			    std::is_constructible<value_type, number_type>::value &&
				is_detected<as_number_function, traits_type>::value &&
				std::is_function<as_number_function<traits_type>>::value &&
				is_as_number_signature<traits_type, value_type, number_type>::value;
		};

		template <typename traits_type>
		using as_integer_function = decltype(traits_type::as_int);

		template <typename traits_type, typename value_type, typename integer_type>
		using is_as_integer_signature = typename std::is_same<as_integer_function<traits_type>, integer_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename integer_type>
		struct supports_as_integer {
			static constexpr auto value =
				std::is_signed<integer_type>::value &&
				not std::is_floating_point<integer_type>::value &&
			    std::is_constructible<value_type, integer_type>::value &&
				is_detected<as_integer_function, traits_type>::value &&
				std::is_function<as_integer_function<traits_type>>::value &&
				is_as_integer_signature<traits_type, value_type, integer_type>::value;
		};

		template <typename traits_type>
		using as_boolean_function = decltype(traits_type::as_bool);

		template <typename traits_type, typename value_type, typename boolean_type>
		using is_as_boolean_signature = typename std::is_same<as_boolean_function<traits_type>, boolean_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename boolean_type>
		struct supports_as_boolean {
			static constexpr auto value =
				std::is_convertible<boolean_type, bool>::value &&
			    std::is_constructible<value_type, boolean_type>::value &&
				is_detected<as_boolean_function, traits_type>::value &&
				std::is_function<as_boolean_function<traits_type>>::value &&
				is_as_boolean_signature<traits_type, value_type, boolean_type>::value;
		};

		template<typename traits>
		struct is_valid_traits {
			// Internal assertions for better feedback
			static_assert(supports_get_type<traits, typename traits::value_type>::value, "traits must provide `jwt::json::type get_type(const value_type&)`");
			static_assert(supports_as_object<traits, typename traits::value_type, typename traits::object_type>::value, "traits must provide `object_type as_object(const value_type&)`");
			static_assert(supports_as_array<traits, typename traits::value_type, typename traits::array_type>::value, "traits must provide `array_type as_array(const value_type&)`");
			static_assert(supports_as_string<traits, typename traits::value_type, typename traits::string_type>::value, "traits must provide `string_type as_string(const value_type&)`");
			static_assert(supports_as_number<traits, typename traits::value_type, typename traits::number_type>::value, "traits must provide `number_type as_number(const value_type&)`");
			static_assert(supports_as_integer<traits, typename traits::value_type, typename traits::integer_type>::value, "traits must provide `integer_type as_int(const value_type&)`");
			static_assert(supports_as_boolean<traits, typename traits::value_type, typename traits::boolean_type>::value, "traits must provide `boolean_type as_bool(const value_type&)`");

			static constexpr auto value =
				supports_get_type<traits, typename traits::value_type>::value &&
				supports_as_object<traits, typename traits::value_type, typename traits::object_type>::value &&
				supports_as_array<traits, typename traits::value_type, typename traits::array_type>::value &&
				supports_as_string<traits, typename traits::value_type, typename traits::string_type>::value &&
				supports_as_number<traits, typename traits::value_type, typename traits::number_type>::value &&
				supports_as_integer<traits, typename traits::value_type, typename traits::integer_type>::value &&
				supports_as_boolean<traits, typename traits::value_type, typename traits::boolean_type>::value;
		};

		template<typename value_type>
		struct is_valid_json_value {
			static constexpr auto value =
				std::is_default_constructible<value_type>::value &&
				std::is_constructible<value_type, const value_type&>::value && // a more generic is_copy_constructible
				std::is_move_constructible<value_type>::value &&
				std::is_assignable<value_type, value_type>::value &&
				std::is_copy_assignable<value_type>::value &&
				std::is_move_assignable<value_type>::value;
				// TODO(cmcarthur): Stream operators
		};

		template<typename value_type, typename string_type, typename object_type>
		struct is_valid_json_object {
			static constexpr auto value =
//TODO New check for json object
//				std::is_same<typename object_type::mapped_type, value_type>::value &&
//				std::is_same<typename object_type::key_type, string_type>::value;
                true;
		};

		template<typename value_type, typename array_type>
		struct is_valid_json_array {
			static constexpr auto value =
//TODO New check for json array
//				std::is_same<typename array_type::value_type, value_type>::value;
                true;
		};

		template<typename value_type, typename string_type, typename object_type, typename array_type>
		struct is_valid_json_types {
			// Internal assertions for better feedback
			static_assert(is_valid_json_value<value_type>::value, "value type must meet basic requirements, default constructor, copyable, moveable");
			static_assert(is_valid_json_object<value_type, string_type, object_type>::value, "object_type must be a string_type to value_type container");
			static_assert(is_valid_json_array<value_type, array_type>::value, "array_type must be a container of value_type");
		
			static constexpr auto value =
				is_valid_json_object<value_type, string_type, object_type>::value &&
				is_valid_json_value<value_type>::value &&
				is_valid_json_array<value_type, array_type>::value;
		};

        // Checks for functions in user supplied json_traits
        // based on: https://stackoverflow.com/a/23133904

        template<typename json_traits, typename object_type, typename string_type>
        struct has_object_count {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<int(*)(const object_type&, const string_type&), &U::object_count>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename value_type, typename object_type, typename string_type>
        struct has_object_get {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<const value_type(*)(const object_type&, const string_type&), &U::object_get>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename value_type, typename object_type, typename string_type>
        struct has_object_set {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<bool(*)(object_type&, const string_type&, const value_type&), &U::object_set>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename value_type, typename object_type, typename string_type>
        struct has_object_for_each {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<void(*)(const object_type&, std::function<void(const string_type&, const value_type&)>), &U::object_for_each>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename string_type>
        struct has_string_to_std {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<std::string(*)(const string_type&), &U::string_to_std>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename string_type>
        struct has_string_from_std {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<string_type(*)(const std::string&), &U::string_from_std>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename string_type>
        struct has_string_hash {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<size_t(*)(const string_type&), &U::string_hash>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename string_type>
        struct has_string_equal {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<bool(*)(const string_type&, const string_type&), &U::string_equal>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename string_type>
        struct has_string_less {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<bool(*)(const string_type&, const string_type&), &U::string_less>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename array_type, typename Iterator>
        struct has_array_construct {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<const array_type(*)(Iterator, Iterator), &U::array_construct>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename value_type, typename array_type>
        struct has_array_get {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<const value_type(*)(const array_type&, const int), &U::array_get>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename value_type, typename array_type>
        struct has_array_set {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<bool(*)(array_type&, const int, const value_type&), &U::array_set>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

        template<typename json_traits, typename value_type, typename array_type>
        struct has_array_for_each {
            template<typename U, U> struct Check;

            template<typename U>
            static std::true_type Test(Check<void(*)(const array_type&, std::function<void(const value_type&)>), &U::array_for_each>*);

            template<typename U>
            static std::false_type Test(...);

            static constexpr bool value = decltype(Test<json_traits>(0))::value;
        };

	}  // namespace details

    template<typename user_json_traits>
    struct default_traits;

    /**
     * \brief a class providing access to registered claim names
     *
     * Static functions to provide the [registered claim names](https://tools.ietf.org/html/rfc7519#section-4.1)
     * The default template parameters use [picojson](https://github.com/kazuho/picojson)
     *
     * \tparam user_json_traits : JSON implementation traits
     *
     * \see [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
     */
    template<typename user_json_traits>
    struct registered_claims{
        using json_traits = default_traits<user_json_traits>;
        static inline constexpr typename json_traits::string_type issuer() {
            return json_traits::string_from_std("iss");
        }

        static inline constexpr typename json_traits::string_type subject() {
            return json_traits::string_from_std("sub");
        }

        static inline constexpr typename json_traits::string_type audience() {
            return json_traits::string_from_std("aud");
        }

        static inline constexpr typename json_traits::string_type expiration_time() {
            return json_traits::string_from_std("exp");
        }

        static inline constexpr typename json_traits::string_type not_before() {
            return json_traits::string_from_std("nbf");
        }

        static inline constexpr typename json_traits::string_type issued_at() {
            return json_traits::string_from_std("iat");
        }

        static inline constexpr typename json_traits::string_type jwt_id() {
            return json_traits::string_from_std("jti");
        }
    };

    /**
     * \brief a class providing access to registered header parameter names
     *
     * Static functions to provide the [JWE registered header parameter names](https://tools.ietf.org/html/rfc7516.html#section-4.1)
     * The default template parameters use [picojson](https://github.com/kazuho/picojson)
     *
     * \tparam user_json_traits : JSON implementation traits
     *
     * \see [RFC 7516: JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
     */
    template<typename user_json_traits>
    struct header_parameters{
        using json_traits = default_traits<user_json_traits>;

        //JWE registered header parameters
        static inline constexpr typename json_traits::string_type algorithm() {
            return json_traits::string_from_std("alg");
        }

        static inline constexpr typename json_traits::string_type encryption_algorithm() {
            return json_traits::string_from_std("enc");
        }

        static inline constexpr typename json_traits::string_type compression_algorithm() {
            return json_traits::string_from_std("zip");
        }

        static inline constexpr typename json_traits::string_type jwk_set_url() {
            return json_traits::string_from_std("jku");
        }

        static inline constexpr typename json_traits::string_type key_id() {
            return json_traits::string_from_std("kid");
        }

        static inline constexpr typename json_traits::string_type x509_url() {
            return json_traits::string_from_std("x5u");
        }

        static inline constexpr typename json_traits::string_type x509_certificate_chain() {
            return json_traits::string_from_std("x5c");
        }

        static inline constexpr typename json_traits::string_type x509_certificate_sha1_thumbprint() {
            return json_traits::string_from_std("x5t");
        }

        static inline constexpr typename json_traits::string_type x509_certificate_sha256_thumbprint() {
            return json_traits::string_from_std("x5t#S256");
        }

        static inline constexpr typename json_traits::string_type type() {
            return json_traits::string_from_std("typ");
        }

        static inline constexpr typename json_traits::string_type content_type() {
            return json_traits::string_from_std("cty");
        }

        static inline constexpr typename json_traits::string_type critical() {
            return json_traits::string_from_std("crit");
        }
    };
	/**
	 * \brief a class to store a generic JSON value as claim
	 * 
	 * The default template parameters use [picojson](https://github.com/kazuho/picojson)
	 * 
     * \tparam user_json_traits : JSON implementation traits
	 * 
	 * \see [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
	 */
    template<typename user_json_traits>
	class basic_claim {
        using json_traits = default_traits<user_json_traits>;
		/**
		 * The reason behind this is to provide an expressive abstraction without
		 * over complexifying the API. For more information take the time to read
		 * https://github.com/nlohmann/json/issues/774. It maybe be expanded to
		 * support custom string types.
		*/
        //TODO Assert valid stringtype
        //static_assert(std::is_same<typename json_traits::string_type, std::string>::value, "string_type must be a std::string.");

		static_assert(details::is_valid_json_types<
            typename json_traits::value_type,
            typename json_traits::string_type,
            typename json_traits::object_type,
            typename json_traits::array_type>::value, "must satisfy json container requirements");
        static_assert(details::is_valid_traits<user_json_traits>::value, "traits must satisfy requirements");

            typename json_traits::value_type val;
		public:

            //Only public because of backwards compatibility
            using set_t = typename default_traits<user_json_traits>::key_set;

			basic_claim() = default;
			basic_claim(const basic_claim&) = default;
			basic_claim(basic_claim&&) noexcept = default;
			basic_claim& operator=(const basic_claim&) = default;
			basic_claim& operator=(basic_claim&&) noexcept = default;
			~basic_claim() = default;

            JWT_CLAIM_EXPLICIT basic_claim(typename json_traits::string_type s)
				: val(std::move(s))
			{}
			JWT_CLAIM_EXPLICIT basic_claim(const date& d)
                : val(typename json_traits::integer_type(std::chrono::system_clock::to_time_t(d)))
			{}
            JWT_CLAIM_EXPLICIT basic_claim(typename json_traits::array_type a)
				: val(std::move(a))
			{}
            JWT_CLAIM_EXPLICIT basic_claim(typename json_traits::value_type v)
				: val(std::move(v))
			{}
            //TODO Make deprecated constructors internal
            [[deprecated("Replaced by basic_claim(array_type), this is just for backwards compatibility")]]
            JWT_CLAIM_EXPLICIT basic_claim(const typename default_traits<user_json_traits>::key_set& s)
                : val(json_traits::array_construct(s.begin(), s.end()))
            {}
            [[deprecated("Replaced by basic_claim(array_type), this is just for backwards compatibility")]]
            JWT_CLAIM_EXPLICIT basic_claim(const std::set<typename json_traits::string_type>& s)
                : val(json_traits::array_construct(s.begin(), s.end()))
            {}
            //TODO The iterator constructor is probably fine
			template<typename Iterator>
			basic_claim(Iterator begin, Iterator end)
                : val(json_traits::array_construct(begin, end))
			{}

			/**
			 * Get wrapped JSON value
			 * \return Wrapped JSON value
			 */
            typename json_traits::value_type to_json() const {
				return val;
			}

			/**
			 * Parse input stream into underlying JSON value
			 * \return input stream
			 */
			std::istream& operator>>(std::istream& is)
            {
                std::string input_string(std::istreambuf_iterator<char>(is), {});
                json_traits::parse(val, json_traits::string_from_std(input_string));
                return is;
			}

			/**
			 * Serialize claim to output stream from wrapped JSON value
			 * \return ouput stream
			 */
			std::ostream& operator<<(std::ostream& os)
			{
                return os << json_traits::string_to_std(json_traits::serialize(val));
			}

			/**
			 * Get type of contained JSON value
			 * \return Type
			 * \throw std::logic_error An internal error occured
			 */
			json::type get_type() const {
                return json_traits::get_type(val);
			}

			/**
			 * Get the contained JSON value as a string
			 * \return content as string
			 * \throw std::bad_cast Content was not a string
			 */
            typename json_traits::string_type as_string() const {
                return json_traits::as_string(val);
			}

			/**
			 * Get the contained JSON value as a date
			 * \return content as date
			 * \throw std::bad_cast Content was not a date
			 */
			date as_date() const {
				return std::chrono::system_clock::from_time_t(as_int());
			}

			/**
			 * Get the contained JSON value as an array
			 * \return content as array
			 * \throw std::bad_cast Content was not an array
			 */
            typename json_traits::array_type as_array() const {
                return json_traits::as_array(val);
			}

			/**
			 * Get the contained JSON value as a set of strings
			 * \return content as set of strings
			 * \throw std::bad_cast Content was not an array of string
			 */
            typename default_traits<user_json_traits>::key_set as_set() const {
                typename default_traits<user_json_traits>::key_set result;
                json_traits::array_for_each(json_traits::as_array(val), [&result](const typename json_traits::value_type& value){
                    result.insert(json_traits::as_string(value));
                });
                return result;
			}

			/**
			 * Get the contained JSON value as an integer
			 * \return content as int
			 * \throw std::bad_cast Content was not an int
			 */
            typename json_traits::integer_type as_int() const {
                return json_traits::as_int(val);
			}

			/**
			 * Get the contained JSON value as a bool
			 * \return content as bool
			 * \throw std::bad_cast Content was not a bool
			 */
            typename json_traits::boolean_type as_bool() const {
                return json_traits::as_bool(val);
			}

			/**
			 * Get the contained JSON value as a number
			 * \return content as double
			 * \throw std::bad_cast Content was not a number
			 */
            typename json_traits::number_type as_number() const {
                return json_traits::as_number(val);
			}
	};

	/**
	 * Base class that represents a token payload.
	 * Contains Convenience accessors for common claims.
	 */
    template<typename user_json_traits>
	class payload {
        using json_traits = default_traits<user_json_traits>;
        using basic_claim_t = basic_claim<user_json_traits>;
    protected:
        typename default_traits<user_json_traits>::claim_map payload_claims;
    public:
		/**
         * Check if issuer is present
		 * \return true if present, false otherwise
		 */
        bool has_issuer() const noexcept { return has_payload_claim(registered_claims<user_json_traits>::issuer()); }
		/**
         * Check if subject is present
		 * \return true if present, false otherwise
		 */
        bool has_subject() const noexcept { return has_payload_claim(registered_claims<user_json_traits>::subject()); }
		/**
         * Check if audience is present
		 * \return true if present, false otherwise
		 */
        bool has_audience() const noexcept { return has_payload_claim(registered_claims<user_json_traits>::audience()); }
		/**
         * Check if expires is present
		 * \return true if present, false otherwise
		 */
        bool has_expires_at() const noexcept { return has_payload_claim(registered_claims<user_json_traits>::expiration_time()); }
		/**
         * Check if not before is present
		 * \return true if present, false otherwise
		 */
        bool has_not_before() const noexcept { return has_payload_claim(registered_claims<user_json_traits>::not_before()); }
		/**
         * Check if issued at is present
		 * \return true if present, false otherwise
		 */
        bool has_issued_at() const noexcept { return has_payload_claim(registered_claims<user_json_traits>::issued_at()); }
		/**
         * Check if token id is present
		 * \return true if present, false otherwise
		 */
        bool has_id() const noexcept { return has_payload_claim(registered_claims<user_json_traits>::jwt_id()); }
		/**
		 * Get issuer claim
		 * \return issuer as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
        typename json_traits::string_type get_issuer() const { return get_payload_claim(registered_claims<user_json_traits>::issuer()).as_string(); }
		/**
		 * Get subject claim
		 * \return subject as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
        typename json_traits::string_type get_subject() const { return get_payload_claim(registered_claims<user_json_traits>::subject()).as_string(); }
        //TODO This should probably return a json_traits::array_type not a key_set
        /**
		 * Get audience claim
		 * \return audience as a set of strings
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a set (Should not happen in a valid token)
		 */
        typename default_traits<user_json_traits>::key_set get_audience() const {
            auto aud = get_payload_claim(registered_claims<user_json_traits>::audience());
			if(aud.get_type() == json::type::string)
				return { aud.as_string() };
			
			return aud.as_set();
		}
		/**
		 * Get expires claim
		 * \return expires as a date in utc
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
        date get_expires_at() const { return get_payload_claim(registered_claims<user_json_traits>::expiration_time()).as_date(); }
		/**
		 * Get not valid before claim
		 * \return nbf date in utc
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
        date get_not_before() const { return get_payload_claim(registered_claims<user_json_traits>::not_before()).as_date(); }
		/**
		 * Get issued at claim
		 * \return issued at as date in utc
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
        date get_issued_at() const { return get_payload_claim(registered_claims<user_json_traits>::issued_at()).as_date(); }
		/**
		 * Get id claim
		 * \return id as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
        typename json_traits::string_type get_id() const { return get_payload_claim(registered_claims<user_json_traits>::jwt_id()).as_string(); }
		/**
		 * Check if a payload claim is present
		 * \return true if claim was present, false otherwise
		 */
        bool has_payload_claim(const typename json_traits::string_type& name) const noexcept { return payload_claims.count(name) != 0; }
		/**
		 * Get payload claim
		 * \return Requested claim
		 * \throw std::runtime_error If claim was not present
		 */
        basic_claim_t get_payload_claim(const typename json_traits::string_type& name) const {
			if (!has_payload_claim(name))
				throw std::runtime_error("claim not found");
			return payload_claims.at(name);
		}
	};

	/**
	 * Base class that represents a token header.
	 * Contains Convenience accessors for common claims.
	 */
    template<typename user_json_traits>
	class header {
        using json_traits = default_traits<user_json_traits>;
        using basic_claim_t = basic_claim<user_json_traits>;
	protected:
        typename default_traits<user_json_traits>::claim_map header_claims;
	public:
		/**
         * Check if algortihm is present
		 * \return true if present, false otherwise
		 */
        bool has_algorithm() const noexcept { return has_header_claim(header_parameters<user_json_traits>::algorithm()); }
		/**
         * Check if type is present
		 * \return true if present, false otherwise
		 */
        bool has_type() const noexcept { return has_header_claim(header_parameters<user_json_traits>::type()); }
		/**
         * Check if content type is present
		 * \return true if present, false otherwise
		 */
        bool has_content_type() const noexcept { return has_header_claim(header_parameters<user_json_traits>::content_type()); }
		/**
         * Check if key id is present
		 * \return true if present, false otherwise
		 */
        bool has_key_id() const noexcept { return has_header_claim(header_parameters<user_json_traits>::key_id()); }
		/**
		 * Get algorithm claim
		 * \return algorithm as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
        typename json_traits::string_type get_algorithm() const { return get_header_claim(header_parameters<user_json_traits>::algorithm()).as_string(); }
		/**
		 * Get type claim
		 * \return type as a string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
        typename json_traits::string_type get_type() const { return get_header_claim(header_parameters<user_json_traits>::type()).as_string(); }
		/**
		 * Get content type claim
		 * \return content type as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
        typename json_traits::string_type get_content_type() const { return get_header_claim(header_parameters<user_json_traits>::content_type()).as_string(); }
		/**
		 * Get key id claim
		 * \return key id as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
        typename json_traits::string_type get_key_id() const { return get_header_claim(header_parameters<user_json_traits>::key_id()).as_string(); }
		/**
		 * Check if a header claim is present
		 * \return true if claim was present, false otherwise
		 */
        bool has_header_claim(const typename json_traits::string_type& name) const noexcept { return header_claims.count(name) != 0; }
		/**
		 * Get header claim
		 * \return Requested claim
		 * \throw std::runtime_error If claim was not present
		 */
        basic_claim_t get_header_claim(const typename json_traits::string_type& name) const {
			if (!has_header_claim(name))
				throw std::runtime_error("claim not found");
			return header_claims.at(name);
		}
	};

	/**
	 * Class containing all information about a decoded token
	 */
    //TODO It is probably better if this class completly operates on std::string
    template<typename user_json_traits>
    class decoded_jwt : public header<user_json_traits>, public payload<user_json_traits> {
        using json_traits = default_traits<user_json_traits>;
	protected:
		/// Unmodifed token, as passed to constructor
        const typename json_traits::string_type token;
		/// Header part decoded from base64
        typename json_traits::string_type header;
		/// Unmodified header part in base64
        typename json_traits::string_type header_base64;
		/// Payload part decoded from base64
        typename json_traits::string_type payload;
		/// Unmodified payload part in base64
        typename json_traits::string_type payload_base64;
		/// Signature part decoded from base64
        typename json_traits::string_type signature;
		/// Unmodified signature part in base64
        typename json_traits::string_type signature_base64;
	public:
	#ifndef DISABLE_BASE64
		/**
		 * Constructor 
		 * Parses a given token
		 * Decodes using the jwt::base64url which supports an std::string
		 * \param token The token to parse
		 * \throw std::invalid_argument Token is not in correct format
		 * \throw std::runtime_error Base64 decoding failed or invalid json
		 */
        JWT_CLAIM_EXPLICIT decoded_jwt(const typename json_traits::string_type& token)
        : decoded_jwt(token, [](const typename json_traits::string_type& token){
                return json_traits::string_from_std(base::decode<alphabet::base64url>(base::pad<alphabet::base64url>(json_traits::string_to_std(token))));
		})
		{}
	#endif
		/**
		 * Constructor 
		 * Parses a given token
		 * \tparam Decode is callabled, taking a string_type and returns a string_type.
		 * It should ensure the padding of the input and then base64url decode and 
		 * return the results.
		 * \param token The token to parse
		 * \param decode The token to parse
		 * \throw std::invalid_argument Token is not in correct format
		 * \throw std::runtime_error Base64 decoding failed or invalid json
		 */
		template<typename Decode>
        decoded_jwt(const typename json_traits::string_type& token, Decode decode)
			: token(token)
		{
            std::string standart_token = json_traits::string_to_std(token);
            auto hdr_end = standart_token.find('.');
            if (hdr_end == std::string::npos)
				throw std::invalid_argument("invalid token supplied");
            auto payload_end = standart_token.find('.', hdr_end + 1);
            if (payload_end == std::string::npos)
				throw std::invalid_argument("invalid token supplied");
            header_base64 = json_traits::string_from_std(standart_token.substr(0, hdr_end));
            payload_base64 = json_traits::string_from_std(standart_token.substr(hdr_end + 1, payload_end - hdr_end - 1));
            signature_base64 = json_traits::string_from_std(standart_token.substr(payload_end + 1));

            header = decode(header_base64);
            payload = decode(payload_base64);
            signature = decode(signature_base64);

            auto parse_claims = [](const typename json_traits::string_type& str) {
                using basic_claim_t = basic_claim<user_json_traits>;
                typename default_traits<user_json_traits>::claim_map res;
                typename json_traits::value_type val;
                if (!json_traits::parse(val, str))
					throw std::runtime_error("Invalid json");

                json_traits::object_for_each(json_traits::as_object(val), [&res](const typename json_traits::string_type& key, const typename json_traits::value_type& value){
                    res.emplace(key, basic_claim_t(value));
                });

				return res;
			};

			this->header_claims = parse_claims(header);
			this->payload_claims = parse_claims(payload);
		}

		/**
		 * Get token string, as passed to constructor
		 * \return token as passed to constructor
		 */
        const typename json_traits::string_type& get_token() const noexcept { return token; }
		/**
		 * Get header part as json string
		 * \return header part after base64 decoding
		 */
        const typename json_traits::string_type& get_header() const noexcept { return header; }
		/**
		 * Get payload part as json string
		 * \return payload part after base64 decoding
		 */
        const typename json_traits::string_type& get_payload() const noexcept { return payload; }
		/**
		 * Get signature part as json string
		 * \return signature part after base64 decoding
		 */
        const typename json_traits::string_type& get_signature() const noexcept { return signature; }
		/**
		 * Get header part as base64 string
		 * \return header part before base64 decoding
		 */
        const typename json_traits::string_type& get_header_base64() const noexcept { return header_base64; }
		/**
		 * Get payload part as base64 string
		 * \return payload part before base64 decoding
		 */
        const typename json_traits::string_type& get_payload_base64() const noexcept { return payload_base64; }
		/**
		 * Get signature part as base64 string
		 * \return signature part before base64 decoding
		 */
        const typename json_traits::string_type& get_signature_base64() const noexcept { return signature_base64; }
		/**
		 * Get all payload claims
		 * \return map of claims
		 */
        typename default_traits<user_json_traits>::claim_map get_payload_claims() const {
			return this->payload_claims;
		}
		/**
		 * Get all header claims
		 * \return map of claims
		 */
        typename default_traits<user_json_traits>::claim_map get_header_claims() const {
			return this->header_claims;
		}
	};

	/**
	 * Builder class to build and sign a new token
	 * Use jwt::create() to get an instance of this class.
	 */
    template<typename user_json_traits>
	class builder {
        using json_traits = default_traits<user_json_traits>;
        typename json_traits::object_type header_claims;
        typename json_traits::object_type payload_claims;
	public:
		builder() = default;
		/**
		 * Set a header claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
        builder& set_header_claim(const typename json_traits::string_type& id, typename json_traits::value_type c)
        { json_traits::object_set(header_claims, id, std::move(c)); return *this; }
		
		/**
		 * Set a header claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
        builder& set_header_claim(const typename json_traits::string_type& id, basic_claim<user_json_traits> c)
        { json_traits::object_set(header_claims, id, c.to_json()); return *this; }
		/**
		 * Set a payload claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
        builder& set_payload_claim(const typename json_traits::string_type& id, typename json_traits::value_type c)
        { json_traits::object_set(payload_claims, id, std::move(c)); return *this; }
		/**
		 * Set a payload claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
        builder& set_payload_claim(const typename json_traits::string_type& id, basic_claim<user_json_traits> c)
        { json_traits::object_set(payload_claims, id, c.to_json()); return *this; }
		/**
		 * Set algorithm claim
		 * You normally don't need to do this, as the algorithm is automatically set if you don't change it.
		 * \param str Name of algorithm
		 * \return *this to allow for method chaining
		 */
        builder& set_algorithm(typename json_traits::string_type str) { return set_header_claim(header_parameters<user_json_traits>::algorithm(), typename json_traits::value_type(str)); }
		/**
		 * Set type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
        builder& set_type(typename json_traits::string_type str) { return set_header_claim(header_parameters<user_json_traits>::type(), typename json_traits::value_type(str)); }
		/**
		 * Set content type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
        builder& set_content_type(typename json_traits::string_type str) { return set_header_claim(header_parameters<user_json_traits>::content_type(), typename json_traits::value_type(str)); }
		/**
		 * Set key id claim
		 * \param str Key id to set
		 * \return *this to allow for method chaining
		 */
        builder& set_key_id(typename json_traits::string_type str) { return set_header_claim(header_parameters<user_json_traits>::key_id(), typename json_traits::value_type(str)); }
		/**
		 * Set issuer claim
		 * \param str Issuer to set
		 * \return *this to allow for method chaining
		 */
        builder& set_issuer(typename json_traits::string_type str) { return set_payload_claim(registered_claims<user_json_traits>::issuer(), typename json_traits::value_type(str)); }
		/**
		 * Set subject claim
		 * \param str Subject to set
		 * \return *this to allow for method chaining
		 */
        builder& set_subject(typename json_traits::string_type str) { return set_payload_claim(registered_claims<user_json_traits>::subject(), typename json_traits::value_type(str)); }
		/**
		 * Set audience claim
		 * \param a Audience set
		 * \return *this to allow for method chaining
		 */
        builder& set_audience(typename json_traits::array_type a) { return set_payload_claim(registered_claims<user_json_traits>::audience(), typename json_traits::value_type(a)); }
		/**
		 * Set audience claim
		 * \param aud Single audience
		 * \return *this to allow for method chaining
		 */
        builder& set_audience(typename json_traits::string_type aud) { return set_payload_claim(registered_claims<user_json_traits>::audience(), typename json_traits::value_type(aud)); }
		/**
		 * Set expires at claim
		 * \param d Expires time
		 * \return *this to allow for method chaining
		 */
        builder& set_expires_at(const date& d) { return set_payload_claim(registered_claims<user_json_traits>::expiration_time(), basic_claim<user_json_traits>(d)); }
		/**
		 * Set not before claim
		 * \param d First valid time
		 * \return *this to allow for method chaining
		 */
        builder& set_not_before(const date& d) { return set_payload_claim(registered_claims<user_json_traits>::not_before(), basic_claim<user_json_traits>(d)); }
		/**
		 * Set issued at claim
		 * \param d Issued at time, should be current time
		 * \return *this to allow for method chaining
		 */
        builder& set_issued_at(const date& d) { return set_payload_claim(registered_claims<user_json_traits>::issued_at(), basic_claim<user_json_traits>(d)); }
		/**
		 * Set id claim
		 * \param str ID to set
		 * \return *this to allow for method chaining
		 */
        builder& set_id(const typename json_traits::string_type& str) { return set_payload_claim(registered_claims<user_json_traits>::jwt_id(), typename json_traits::value_type(str)); }

		/**
		 * Sign token and return result
		 * \tparam Algo Callable method which takes a string_type and return the signed input as a string_type
		 * \tparam Encode Callable method which takes a string_type and base64url safe encodes it,
		 * MUST return the result with no padding; trim the result.
		 * \param algo Instance of an algorithm to sign the token with
		 * \param encode Callable to transform the serialized json to base64 with no padding
		 * \return Final token as a string
		 * 
		 * \note If the 'alg' header in not set in the token it will be set to `algo.name()`
		 */
		template<typename Algo, typename Encode>
        typename json_traits::string_type sign(const Algo& algo, Encode encode) const {
            typename json_traits::object_type obj_header = header_claims;
            if(json_traits::object_count(header_claims, header_parameters<user_json_traits>::algorithm()) == 0)
                json_traits::object_set(obj_header, header_parameters<user_json_traits>::algorithm(), typename json_traits::value_type(json_traits::string_from_std(algo.name())));

            //Quite a lot of conversions, because:
            // The encode function should work with the json stringtype
            // I dont want to rely on the json string implementing operator+
            std::string header = json_traits::string_to_std(encode(json_traits::serialize(typename json_traits::value_type(obj_header))));
            std::string payload = json_traits::string_to_std(encode(json_traits::serialize(typename json_traits::value_type(payload_claims))));
            std::string token = header + "." + payload;

            return json_traits::string_from_std(token + "." + json_traits::string_to_std(encode(json_traits::string_from_std(algo.sign(token)))));
		}
	#ifndef DISABLE_BASE64
		/**
		 * Sign token and return result
		 * 
		 * using the `jwt::base` functions provided
		 * 
		 * \param algo Instance of an algorithm to sign the token with
		 * \return Final token as a string
		 */
		template<typename Algo>
        typename json_traits::string_type sign(const Algo& algo) const {
            return sign(algo, [](const typename json_traits::string_type& data) {
                return json_traits::string_from_std(base::trim<alphabet::base64url>(base::encode<alphabet::base64url>(json_traits::string_to_std(data))));
			});
		}
	#endif
	};

	/**
	 * Verifier class used to check if a decoded token contains all claims required by your application and has a valid signature.
	 */
    template<typename Clock, typename user_json_traits>
	class verifier {
        using json_traits = default_traits<user_json_traits>;
		struct algo_base {
			virtual void verify(const std::string& data, const std::string& sig) = 0;
		};
		template<typename T>
		struct algo : public algo_base {
			T alg;
			explicit algo(T a) : alg(a) {}
			void verify(const std::string& data, const std::string& sig) override {
				alg.verify(data, sig);
			}
		};

        using basic_claim_t = basic_claim<user_json_traits>;
		/// Required claims
        typename default_traits<user_json_traits>::claim_map claims;
        /// Leeway time for exp, nbf and iat
		size_t default_leeway = 0;
		/// Instance of clock type
		Clock clock;
		/// Supported algorithms
		std::unordered_map<std::string, std::shared_ptr<algo_base>> algs;
	public:
		/**
		 * Constructor for building a new verifier instance
		 * \param c Clock instance
		 */
        explicit verifier(Clock c) : clock(c) {}

		/**
		 * Set default leeway to use.
		 * \param leeway Default leeway to use if not specified otherwise
		 * \return *this to allow chaining
		 */
		verifier& leeway(size_t leeway) { default_leeway = leeway; return *this; }
		/**
		 * Set leeway for expires at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for expires at.
		 * \return *this to allow chaining
		 */
        verifier& expires_at_leeway(size_t leeway) { return with_claim(registered_claims<user_json_traits>::expiration_time(), basic_claim_t(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set leeway for not before.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for not before.
		 * \return *this to allow chaining
		 */
        verifier& not_before_leeway(size_t leeway) { return with_claim(registered_claims<user_json_traits>::not_before(), basic_claim_t(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set leeway for issued at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for issued at.
		 * \return *this to allow chaining
		 */
        verifier& issued_at_leeway(size_t leeway) { return with_claim(registered_claims<user_json_traits>::issued_at(), basic_claim_t(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set an issuer to check for.
		 * Check is casesensitive.
		 * \param iss Issuer to check for.
		 * \return *this to allow chaining
		 */
        verifier& with_issuer(const typename json_traits::string_type& iss) { return with_claim(registered_claims<user_json_traits>::issuer(), basic_claim_t(iss)); }
		/**
		 * Set a subject to check for.
		 * Check is casesensitive.
         * \param sub Subject to check for.
		 * \return *this to allow chaining
		 */
        verifier& with_subject(const typename json_traits::string_type& sub) { return with_claim(registered_claims<user_json_traits>::subject(), basic_claim_t(sub)); }
        //TODO deprecate both with_audience(set) methods, as the key_set type should just be internal
        /**
         * Set an audience to check for.
         * If any of the specified audiences is not present in the token the check fails.
         * \param aud Audience to check for.
         * \return *this to allow chaining
         * \deprecated Replaced by with_audience(array_type),this is just for backwards compatibility and should be internal
         */
        [[deprecated("Replaced by with_audience(array_type), this is just for backwards compatibility")]]
        verifier& with_audience(const typename default_traits<user_json_traits>::key_set& aud) { return with_claim(registered_claims<user_json_traits>::audience(), basic_claim_t(aud.begin(), aud.end())); }
        /**
         * Set an audience to check for.
         * If any of the specified audiences is not present in the token the check fails.
         * \param aud Audience to check for.
         * \return *this to allow chaining
         * \deprecated Replaced by with_audience(array_type), this is just for backwards compatibility
         */
        [[deprecated("Replaced by with_audience(array_type), this is just for backwards compatibility")]]
        verifier& with_audience(const typename std::set<typename json_traits::string_type>& aud) {
            typename default_traits<user_json_traits>::key_set correctSet(aud.begin(), aud.end());
            return with_audience(correctSet);
        }
        /**
		 * Set an audience to check for.
		 * If any of the specified audiences is not present in the token the check fails.
		 * \param aud Audience to check for.
		 * \return *this to allow chaining
		 */
        verifier& with_audience(const typename json_traits::array_type& aud) { return with_claim(registered_claims<user_json_traits>::audience(), basic_claim_t(aud)); }
		/**
		 * Set an audience to check for.
		 * If the specified audiences is not present in the token the check fails.
		 * \param aud Audience to check for.
		 * \return *this to allow chaining
		 */
        verifier& with_audience(const typename json_traits::string_type& aud) { return with_claim(registered_claims<user_json_traits>::audience(), basic_claim_t(aud)); }
		/**
		 * Set an id to check for.
		 * Check is casesensitive.
		 * \param id ID to check for.
		 * \return *this to allow chaining
		 */
        verifier& with_id(const typename json_traits::string_type& id) { return with_claim(registered_claims<user_json_traits>::jwt_id(), basic_claim_t(id)); }
		/**
		 * Specify a claim to check for.
		 * \param name Name of the claim to check for
		 * \param c Claim to check for
		 * \return *this to allow chaining
		 */
        verifier& with_claim(const typename json_traits::string_type& name, basic_claim_t c) { claims[name] = c; return *this; }

		/**
		 * Add an algorithm available for checking.
		 * \param alg Algorithm to allow
		 * \return *this to allow chaining
		 */
		template<typename Algorithm>
		verifier& allow_algorithm(Algorithm alg) {
			algs[alg.name()] = std::make_shared<algo<Algorithm>>(alg);
			return *this;
		}

		/**
		 * Verify the given token.
		 * \param jwt Token to check
		 * \throw token_verification_exception Verification failed
		 */
        void verify(const decoded_jwt<user_json_traits>& jwt) const {
            const std::string data = json_traits::string_to_std(jwt.get_header_base64()) + "." + json_traits::string_to_std(jwt.get_payload_base64());
            const std::string sig = json_traits::string_to_std(jwt.get_signature());
            const std::string algo = json_traits::string_to_std(jwt.get_algorithm());
			if (algs.count(algo) == 0)
				throw token_verification_exception("wrong algorithm");
			algs.at(algo)->verify(data, sig);

            auto assert_claim_eq = [](const decoded_jwt<user_json_traits>& jwt, const typename json_traits::string_type& key, const basic_claim_t& c) {
				if (!jwt.has_payload_claim(key))
                    throw token_verification_exception("decoded_jwt is missing " + json_traits::string_to_std(key) + " claim");
				auto jc = jwt.get_payload_claim(key);
				if (jc.get_type() != c.get_type())
                    throw token_verification_exception("claim " + json_traits::string_to_std(key) + " type mismatch");
				if (c.get_type() == json::type::integer) {
					if (c.as_date() != jc.as_date())
                        throw token_verification_exception("claim " + json_traits::string_to_std(key) + " does not match expected");
				}
				else if (c.get_type() == json::type::array) {
					auto s1 = c.as_set();
					auto s2 = jc.as_set();
					if (s1.size() != s2.size())
                        throw token_verification_exception("claim " + json_traits::string_to_std(key) + " does not match expected");
                    auto it1 = s1.cbegin();
                    auto it2 = s2.cbegin();
                    //TODO comparing an array of things other than strings
                    while (it1 != s1.cend() && it2 != s2.cend()) {
                        if (!json_traits::string_equal(*it1++, *it2++))
                            throw token_verification_exception("claim " + json_traits::string_to_std(key) + " does not match expected");
                    }
                }
                else if (c.get_type() == json::type::object) {
                    if (!json_traits::string_equal( json_traits::serialize(c.to_json()), json_traits::serialize(jc.to_json()) ))
                        throw token_verification_exception("claim " + json_traits::string_to_std(key) + " does not match expected");
                }
                else if (c.get_type() == json::type::string) {
                    if (!json_traits::string_equal(c.as_string(), jc.as_string()))
                        throw token_verification_exception("claim " + json_traits::string_to_std(key) + " does not match expected");
				}
				else throw token_verification_exception("internal error");
			};

			auto time = clock.now();

            if (jwt.has_expires_at()) {
                auto leeway = claims.count(registered_claims<user_json_traits>::expiration_time()) == 1 ? std::chrono::system_clock::to_time_t(claims.at(registered_claims<user_json_traits>::expiration_time()).as_date()) : default_leeway;
                auto exp = jwt.get_expires_at();
                if (time > exp + std::chrono::seconds(leeway))
                    throw token_verification_exception("token expired");
            }
            if (jwt.has_issued_at()) {
                auto leeway = claims.count(registered_claims<user_json_traits>::issued_at()) == 1 ? std::chrono::system_clock::to_time_t(claims.at(registered_claims<user_json_traits>::issued_at()).as_date()) : default_leeway;
                auto iat = jwt.get_issued_at();
                if (time < iat - std::chrono::seconds(leeway))
                    throw token_verification_exception("token expired");
            }
            if (jwt.has_not_before()) {
                auto leeway = claims.count(registered_claims<user_json_traits>::not_before()) == 1 ? std::chrono::system_clock::to_time_t(claims.at(registered_claims<user_json_traits>::not_before()).as_date()) : default_leeway;
                auto nbf = jwt.get_not_before();
                if (time < nbf - std::chrono::seconds(leeway))
                    throw token_verification_exception("token expired");
            }
            for (auto& c : claims)
            {
                if (json_traits::string_equal(c.first, registered_claims<user_json_traits>::expiration_time()) || json_traits::string_equal(c.first, registered_claims<user_json_traits>::issued_at()) || json_traits::string_equal(c.first, registered_claims<user_json_traits>::not_before())) {
                    // Nothing to do here, already checked
                }
                else if (json_traits::string_equal(c.first, registered_claims<user_json_traits>::audience())) {
                    if (!jwt.has_audience())
                        throw token_verification_exception("token doesn't contain the required audience");
                    auto aud = jwt.get_audience();
                    auto expected = c.second.as_set();
                    for (auto& e : expected)
                        if (aud.count(e) == 0)
                            throw token_verification_exception("token doesn't contain the required audience");
                }
                else {
                    assert_claim_eq(jwt, c.first, c.second);
                }
            }
		}
	};

    /** TODO
     * A proxy to the functions of json_traits
     * Asserts that json_traits has all neccessary functions and
     * provides default implementations if some are missing
     * Providing claim_map and key_set
     */
    template<typename json_traits>
    struct default_traits{
    public:
        using value_type = typename json_traits::value_type;
        using object_type = typename json_traits::object_type;
        using array_type = typename json_traits::array_type;
        using string_type = typename json_traits::string_type;
        using number_type = typename json_traits::number_type;
        using integer_type = typename json_traits::integer_type;
        using boolean_type = typename json_traits::boolean_type;
    private:
        class key_compare{
        public:
            bool operator()(const string_type &lhs, const string_type &rhs) const
            {
                return string_less(lhs, rhs);
            }
        };

        class key_equal{
        public:
            bool operator()(const string_type &lhs, const string_type &rhs) const
            {
                return string_equal(lhs, rhs);
            }
        };

        class key_hash{
        public:
            bool operator()(const string_type &string) const
            {
                return string_hash(string);
            }
        };
    public:
        using claim_map = std::unordered_map<string_type, basic_claim<json_traits>, key_hash, key_equal>;
        using key_set = std::set<string_type, key_compare>;

        static json::type get_type(const value_type& val) {
            return json_traits::get_type(val);
        }

        static object_type as_object(const value_type& val) {
            return json_traits::as_object(val);
        }

        static string_type as_string(const value_type& val) {
            return json_traits::as_string(val);
        }

        static array_type as_array(const value_type& val) {
            return json_traits::as_array(val);
        }

        static integer_type as_int(const value_type& val) {
            return json_traits::as_int(val);
        }

        static boolean_type as_bool(const value_type& val) {
            return json_traits::as_bool(val);
        }

        static number_type as_number(const value_type& val) {
            return json_traits::as_number(val);
        }

        static bool parse(value_type& value, const string_type& str){
            return json_traits::parse(value,str);
        }

        static string_type serialize(const value_type& val){
            return json_traits::serialize(val);
        }

        //Functions for json objects
        template<class Q = json_traits>
        static typename std::enable_if<details::has_object_count<Q, object_type, string_type>::value, int>::type object_count(const object_type& object, const string_type& key) {
            return json_traits::object_count(object, key);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_object_count<Q, object_type, string_type>::value, int>::type object_count(const object_type& object, const string_type& key) {
            //TODO default implementation
            return 5;
        }

        template<class Q = json_traits>
        static const typename std::enable_if<details::has_object_get<Q, value_type, object_type, string_type>::value, value_type>::type object_get(const object_type& object, const string_type& key) {
            return json_traits::object_get(object, key);
        }

        template<class Q = json_traits>
        static const typename std::enable_if<!details::has_object_get<Q, value_type, object_type, string_type>::value, value_type>::type object_get(const object_type& object, const string_type& key) {
            //TODO default implementation
            return value_type(5);
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_object_set<Q, value_type, object_type, string_type>::value, bool>::type object_set(object_type& object, const string_type& key, const value_type& value) {
            return json_traits::object_set(object,key,value);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_object_set<Q, value_type, object_type, string_type>::value, bool>::type object_set(object_type& object, const string_type& key, const value_type& value) {
            //TODO default implementation
            return false;
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_object_for_each<Q, value_type, object_type, string_type>::value, void>::type object_for_each(const object_type& object, std::function<void(const string_type&, const value_type&)> function) {
            return json_traits::object_for_each(object,function);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_object_for_each<Q, value_type, object_type, string_type>::value, void>::type object_for_each(const object_type& object, std::function<void(const string_type&, const value_type&)> function) {
            //TODO default implementation
            return;
        }

        //Functions for json strings
        template<class Q = json_traits>
        static typename std::enable_if<details::has_string_to_std<Q, string_type>::value, std::string>::type string_to_std(const string_type& string) {
            return json_traits::string_to_std(string);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_string_to_std<Q, string_type>::value, std::string>::type string_to_std(const string_type& string) {
            //TODO default implementation
            return "";
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_string_from_std<Q, string_type>::value, string_type>::type string_from_std(const std::string& string) {
            return json_traits::string_from_std(string);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_string_from_std<Q, string_type>::value, string_type>::type string_from_std(const std::string& string) {
            //TODO default implementation
            return "";
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_string_hash<Q, string_type>::value, size_t>::type string_hash(const string_type& string){
            return json_traits::string_hash(string);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_string_hash<Q, string_type>::value, size_t>::type string_hash(const string_type& string){
            //TODO default implementation
            return 0;
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_string_equal<Q, string_type>::value, bool>::type string_equal(const string_type& string_a, const string_type& string_b){
            return json_traits::string_equal(string_a, string_b);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_string_equal<Q, string_type>::value, bool>::type string_equal(const string_type& string_a, const string_type& string_b){
            //TODO default implementation
            return false;
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_string_less<Q, string_type>::value, bool>::type string_less(const string_type& string_a, const string_type& string_b){
            return json_traits::string_less(string_a, string_b);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_string_less<Q, string_type>::value, bool>::type string_less(const string_type& string_a, const string_type& string_b){
            //TODO default implementation
            return false;
        }

        //Functions for json arrays
        template<typename Iterator, class Q = json_traits>
        static const typename std::enable_if<details::has_array_construct<Q, array_type, Iterator>::value, array_type>::type array_construct(Iterator begin, Iterator end){
            return json_traits::array_construct(begin, end);
        }

        template<typename Iterator, class Q = json_traits>
        static const typename std::enable_if<!details::has_array_construct<Q, array_type, Iterator>::value, array_type>::type array_construct(Iterator begin, Iterator end){
            //TODO default implementation
            return array_type();
        }

        template<class Q = json_traits>
        static const typename std::enable_if<details::has_array_get<Q, value_type, array_type>::value, value_type>::type array_get(const array_type& array, const int index) {
            return json_traits::array_get(array, index);
        }

        template<class Q = json_traits>
        static const typename std::enable_if<!details::has_array_get<Q, value_type, array_type>::value, value_type>::type array_get(const array_type& array, const int index) {
            //TODO default implementation
            return value_type(0);
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_array_set<Q, value_type, array_type>::value, bool>::type array_set(array_type& array, const int index, const value_type& value) {
            return json_traits::array_set(array, index, value);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_array_set<Q, value_type, array_type>::value, bool>::type array_set(array_type& array, const int index, const value_type& value) {
            //TODO default implementation
            return false;
        }

        template<class Q = json_traits>
        static typename std::enable_if<details::has_array_for_each<Q, value_type, array_type>::value, void>::type array_for_each(const array_type& array, std::function<void(const value_type&)> function) {
            return json_traits::array_for_each(array, function);
        }

        template<class Q = json_traits>
        static typename std::enable_if<!details::has_array_for_each<Q, value_type, array_type>::value, void>::type array_for_each(const array_type& array, std::function<void(const value_type&)> function) {
            //TODO default implementation
            return;
        }
    };

    /**
	 * Create a verifier using the given clock
	 * \param c Clock instance to use
	 * \return verifier instance
	 */
	template<typename Clock, typename json_traits>
	verifier<Clock, json_traits> verify(Clock c) {
		return verifier<Clock, json_traits>(c);
	}

	/**
	 * Default clock class using std::chrono::system_clock as a backend.
	 */
	struct default_clock {
		date now() const {
			return date::clock::now();
		}
	};

	/**
	 * Return a builder instance to create a new token
	 */
	template<typename json_traits>
	builder<json_traits> create() {
		return builder<json_traits>();
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \param decode function that will pad and base64url decode the token
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	template<typename json_traits, typename Decode>
	decoded_jwt<json_traits> decode(const typename json_traits::string_type& token, Decode decode) {
		return decoded_jwt<json_traits>(token, decode);
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	template<typename json_traits>
	decoded_jwt<json_traits> decode(const typename json_traits::string_type& token) {
		return decoded_jwt<json_traits>(token);
	}

#ifndef DISABLE_PICOJSON
	struct picojson_traits {
		using value_type = picojson::value;
		using object_type = picojson::object;
		using array_type = picojson::array;
		using string_type = std::string;
		using number_type = double;
		using integer_type = int64_t;
		using boolean_type = bool;

		static json::type get_type(const picojson::value& val) {
			using json::type;
			if (val.is<bool>()) return type::boolean;
			if (val.is<int64_t>()) return type::integer;
			if (val.is<double>()) return type::number;
			if (val.is<std::string>()) return type::string;
			if (val.is<picojson::array>()) return type::array;
			if (val.is<picojson::object>()) return type::object;

			throw std::logic_error("invalid type");
		}

		static picojson::object as_object(const picojson::value& val) {
			if (!val.is<picojson::object>())
				throw std::bad_cast();
			return val.get<picojson::object>();
		}

		static std::string as_string(const picojson::value& val) {
			if (!val.is<std::string>())
				throw std::bad_cast();
			return val.get<std::string>();
		}

		static picojson::array as_array(const picojson::value& val) {
			if (!val.is<picojson::array>())
				throw std::bad_cast();
			return val.get<picojson::array>();
		}

		static int64_t as_int(const picojson::value& val) {
			if (!val.is<int64_t>())
				throw std::bad_cast();
			return val.get<int64_t>();
		}

		static bool as_bool(const picojson::value& val) {
			if (!val.is<bool>())
				throw std::bad_cast();
			return val.get<bool>();
		}

		static double as_number(const picojson::value& val) {
			if (!val.is<double>())
				throw std::bad_cast();
			return val.get<double>();
		}

		static bool parse(picojson::value& val, const std::string& str){
			return picojson::parse(val, str).empty();
		}

		static std::string serialize(const picojson::value& val){
			return val.serialize();
		}

        //Functions for json objects
        static int object_count(const object_type& object, const string_type& key) {
            return object.count(key);
        }

        static const value_type object_get(const object_type& object, const string_type& key) {
            return object.at(key);
        }

        static bool object_set(object_type& object, const string_type& key, const value_type& value) {
            object[key] = value;
            return true;
        }

        static void object_for_each(const object_type& object, std::function<void(const string_type&, const value_type&)> function) {
            for(const auto& value : object){
                function(value.first, value.second);
            }
        }

        //Functions for json strings
        static std::string string_to_std(const string_type& string) {
            return string;
        }

        static string_type string_from_std(const std::string& string) {
            return string;
        }

        static size_t string_hash(const string_type& string){
            return std::hash<string_type>()(string);
        }

        static bool string_equal(const string_type& string_a, const string_type& string_b){
            return (string_a == string_b);
        }

        static bool string_less(const string_type& string_a, const string_type& string_b){
            return 0 < string_a.compare(string_b);
        }

        //Functions for json arrays
        template<typename Iterator>
        static const array_type array_construct(Iterator begin, Iterator end){
            return array_type(begin, end);
        }

        static const value_type array_get(const array_type& array, const int index) {
            return array.at(index);
        }

        static bool array_set(array_type& array, const int index, const value_type& value) {
            array[index] = value;
            return true;
        }

        static void array_for_each(const array_type& array, std::function<void(const value_type&)> function) {
            for(const value_type& value : array){
                function(value);
            }
        }
	};

	/**
	 * Default JSON claim
	 * 
	 * This type is the default specialization of the \ref basic_claim class which
	 * uses the standard template types.
	 */
	using claim = basic_claim<picojson_traits>;

	/**
	 * Create a verifier using the default clock
	 * \return verifier instance
	 */
	inline
	verifier<default_clock, picojson_traits> verify() {
		return verify<default_clock, picojson_traits>(default_clock{});
	}
	/**
	 * Return a picojson builder instance to create a new token
	 */
	inline
	builder<picojson_traits> create() {
		return builder<picojson_traits>();
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	inline
	decoded_jwt<picojson_traits> decode(const std::string& token) {
		return decoded_jwt<picojson_traits>(token);
	}
#endif
}  // namespace jwt

template<typename json_traits>
std::istream& operator>>(std::istream& is, jwt::basic_claim<json_traits>& c)
{
	return c.operator>>(is);
}

template<typename json_traits>
std::ostream& operator<<(std::ostream& os, const jwt::basic_claim<json_traits>& c)
{
	return os << c.to_json();
}

#endif
