package com.reeuse.androidkeystore;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Base64;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * To store and retrieve sensitive information using Android Keystore.
 * Created by Rajiv M on 28/04/17.
 */

public class SecurityHelper {

  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
  private static final String CHARACTER_SET_UTF_8 = "UTF-8";

  private byte[] encryption;
  private byte[] iv;

  public SecurityHelper() {
    // Default Constructor.
  }

  // ------------------------------------------- Encryption methods -------------------------------------------------- //

  /**
   * This method is to get the secret key from android keystore and to encrypt the given plain text.
   * @param alias this is key/name (reference) to fetch the secret value.
   * @param textToEncrypt plain text to encrypt.
   * @return String -encrypted string value.
   * @throws UnrecoverableEntryException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws IOException
   * @throws InvalidAlgorithmParameterException
   * @throws SignatureException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  String encrypt(final String alias, final String textToEncrypt)
      throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
      NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
      InvalidAlgorithmParameterException, SignatureException, BadPaddingException,
      IllegalBlockSizeException {
    //Crypto transformation technique we are gonna follow is AES/GCM/NoPadding.
    final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    //Generate and get the secret key by passing the alias name.
    SecretKey secretKey = createSecretKey(alias);
    //pass the secret key and encrypt it.
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    //vector(IV) random value.
    iv = cipher.getIV();
    byte[] encryptedValue =
        encryption = cipher.doFinal(textToEncrypt.getBytes(CHARACTER_SET_UTF_8));
    // return the encrypted base64 string
    return Base64.encodeToString(encryptedValue, Base64.DEFAULT);
  }

  /**
   * This method is get the secret from android keystore by passing the alias.
   * @param alias is reference to get the secret.
   * @return SecretKey- value.
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidAlgorithmParameterException
   */
  private SecretKey createSecretKey(final String alias)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    final KeyGenerator keyGenerator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
    keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(
        KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build());
    return keyGenerator.generateKey();
  }

  /**
   * This method return the encrypted value of the plain text.
   * @return byte[] encrpted value.
   */
  byte[] getEncryption() {
    return encryption;
  }

  /**
   * This method return the salt value used for the encryption.
   * @return byte [] random salt value.
   */
  byte[] getIv() {
    return iv;
  }

  // ------------------------------------------- Decryption methods -------------------------------------------------- //

  /**
   * To decrypt the secret value.
   * @param alias name given for the secret at the time of encryption.
   * @param encryptedData encrypted data.
   * @param encryptionIv salt value.
   * @return String plain text.
   * @throws UnrecoverableEntryException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws IOException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws CertificateException
   */
  String decrypt(final String alias, final byte[] encryptedData, final byte[] encryptionIv)
      throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
      NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
      BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException,
      CertificateException {

    final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    //authentication tag 128, 120, 112, 104, 96 we are using 128 now.
    final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
    cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias), spec);
    // return the decrypted string.
    return new String(cipher.doFinal(encryptedData), CHARACTER_SET_UTF_8);
  }

  /**
   * To get the corresponding SecretKey value from Android keystore
   * @param alias name used at the time of encryption.
   * @return SecretKey value.
   * @throws NoSuchAlgorithmException
   * @throws UnrecoverableEntryException
   * @throws KeyStoreException
   * @throws IOException
   * @throws CertificateException
   */
  private SecretKey getSecretKey(final String alias)
      throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, IOException,
      CertificateException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
    keyStore.load(null);
    return ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null)).getSecretKey();
  }
}
