#!/usr/bin/php
<?php

class My_GPG {
	public function __construct() {
		putenv('GNUPGHOME=/home/user/.gnupg');
		$this->gpg = new gnupg();
		$this->gpg->seterrormode(gnupg::ERROR_EXCEPTION);
	}

	/**
	 * @brief Encrypt plaintext
	 *
	 * @param  string  $plaintext
	 * @param  string  $fingerprint
	 *
	 * @return string  Encrypted ciphertext
	 */
	public function encrypt($plaintext, $fingerprint) {
		// Remove whitespace
		$fingerprint = str_replace(' ', '', $fingerprint);

		try {
			$encrypted = $this->gpg->encrypt($plaintext);
		} catch (Exception $e) {
			echo "Exception: " . $e;
		}

		return $encrypted;
	}

	/**
	 * @brief Encrypt file
	 *
	 * @param  string  $path         Path to plain file
	 * @param  string  $fingerprint
	 *
	 * @return string Path to encrypted file
	 */
	public function encrypt_file($path, $fingerprint) {
		// Set destination
		$out_path = $path . ".gpg";

		// Encrypt
		$encrypted = $this->encrypt(file_get_contents($path), $fingerprint);

		// Write encrypted data to file
		file_put_contents($out_path, $encrypted);

		return $out_path;
	}

	/**
	 * @brief Decrypt a GPG-encrypted ciphertext
	 *
	 * @param  string  $ciphertext
	 *
	 * @return string Decrypted plaintext
	 */
	public function decrypt($ciphertext) {
		try {
			$decrypted = $this->gpg->decrypt($ciphertext);
		} catch (Exception $e) {
			echo "Exception: " . $e;
		}

		return $decrypted;
	}

	/**
	* @brief Decrypt a GPG-encrypted file
	*
	* @param  string  $path
	*
	* @return string Path to decrypted file
	*/
	public function decrypt_file($path) {
		// Set destination
		$out_path = dirname($path) . "/" . pathinfo($path, PATHINFO_FILENAME);

		// Decrypt
		$decrypted = $this->decrypt(file_get_contents($path));

		// Write decrypted data to file
		file_put_contents($out_path, $decrypted);

		return $out_path;
	}

	/**
	 * @brief Import a public key
	 *
	 * @param  string  $keydata  Entire content of the public-key file
	 *
	 * @return boolean
	 */
	public function add_key($key_path) {
		// Import key
		$info = $this->gpg->import(file_get_contents($key_path));

		if ($info) {
			// Add encrypt key
			$this->gpg->addencryptkey($info['fingerprint']);

			// Add decrypt key
			$this->gpg->adddecryptkey($info['fingerprint'], "");
		}
		else {
			return false;
		}
	}
}
