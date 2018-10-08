#!/bin/bash

##########################
# Encrypt text with GPG
# Arguments:
#   None
# Returns:
#   None
##########################
encrypt_text() {
    # Get info
    read -p "Enter Recipient: " recipient
    read -p "Enter text to encrypt: " plaintext

    # Encrypt
    echo ${plaintext} | gpg --encrypt --recipient ${recipient} --armor

    echo
}

####################################
# Decrypt text encrypted with GPG
# Arguments:
#   None
# Returns:
#   None
####################################
decrypt_text() {
    echo

    # Set destination
    path=/tmp/gpg_$(date +%s).txt

    # Get ciphertext
    read -p "Enter ciphertext in editor (Press any key to continue)"
    "${EDITOR:-nano}" ${path}

    # Decrypt
    echo "Decrypted:"
    gpg --decrypt ${path}

    # Cleanup
    rm ${path}
    echo
}

##########################
# Encrypt file with GPG
# Arguments:
#   None
# Returns:
#   None
##########################
encrypt_file() {
    echo

    # Get info
    read -p "Enter Recipient: " recipient
    read -p "Enter path: " -e path

    # Encrypt
    gpg --output ${path}.gpg --encrypt --recipient ${recipient} ${path}

    echo
}

####################################
# Decrypt file encrypted with GPG
# Arguments:
#   None
# Returns:
#   None
####################################
decrypt_file() {
    echo

    # Get path
    read -p "Enter path: " -e path

    # Remove '.gpg'
    filename=$(basename -- "$path")
    extension="${filename##*.}"

    if [ "${filename##*.}" = "gpg" ]; then
        outname="${filename%.*}"
    else
        outname=${filename}_dec.${extension}
    fi

    # Decrypt
    gpg --output $(dirname "${path}")/${outname} --decrypt ${path}

    echo
}

PS3='Enter your choice: '
options=("Encrypt Text" "Decrypt Text" "Encrypt File" "Decrypt File" "Exit")
select opt in "${options[@]}"
do
    case $opt in
        "Encrypt Text")
            encrypt_text
            ;;
        "Decrypt Text")
            decrypt_text
            ;;
        "Encrypt File")
            encrypt_file
            ;;
        "Decrypt File")
            decrypt_file
            ;;
        "Exit")
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done
