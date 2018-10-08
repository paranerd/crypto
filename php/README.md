# How To Use GnuPG
## Setup GnuPG on the server
```bash
sudo apt install php7.0-dev libgpgme11-dev php-pear
sudo pecl install gnupg
```

If you're using Apache2
```bash
echo "extension=gnupg.so" | sudo tee -a /etc/php/7.0/apache2/php.ini
```

If you're on CLI
```bash
echo "extension=gnupg.so" | sudo tee -a /etc/php/7.0/cli/php.ini
```

Restart apache
```bash
sudo service apache2 restart
```

or, if you're working with CLI

```bash
sudo service php7.0-fpm restart
```

## Generate a key-pair (if not exists)
```bash
gpg --gen-key
```

Get a list of all the keys
```bash
gpg --list-keys
```
Note 8-character-hex-value after the keylength (so after '4096R/', '2048R/', etc.)

Get public key
```bash
gpg -a --export [hex-value] > public.key
```

Get private key
```bash
gpg -a --export-secret-keys [hex-value] > private.key
```

## Import keys in PHP
```php
My_GPG->add_key(<path_to_public.key>);
My_GPG->add_key(<path_to_private.key>);
```

## Encrypt text
Get the fingerprint of the key you want to encrypt with
```bash
gpg --fingerprint
```

```php
$gpg = new My_GPG();
$gpg->encrypt('this is a test', "FINGERPRINT");
```

## Decrypt text
```php
$gpg = new My_GPG();
$gpg->decrypt("encrypted_text");
```
