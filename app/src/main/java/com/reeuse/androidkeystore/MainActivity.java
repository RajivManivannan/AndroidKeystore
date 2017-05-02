package com.reeuse.androidkeystore;

import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

  private static final String TAG = MainActivity.class.getSimpleName();
  private static final String ALIAS = "ALIAS_ONE";// It is key  to fetch the actual value.

  EditText edTextToEncrypt;
  TextView tvEncryptedText;
  TextView tvDecryptedText;

  private SecurityHelper securityHelper;

  @Override protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    edTextToEncrypt = (EditText) findViewById(R.id.ed_text_to_encrypt);
    tvEncryptedText = (TextView) findViewById(R.id.tv_encrypted_text);
    tvDecryptedText = (TextView) findViewById(R.id.tv_decrypted_text);

    securityHelper = new SecurityHelper();

    findViewById(R.id.btn_encrypt).setOnClickListener(new View.OnClickListener() {
      @RequiresApi(api = Build.VERSION_CODES.M) @Override public void onClick(View v) {
        encryptText();
      }
    });

    findViewById(R.id.btn_decrypt).setOnClickListener(new View.OnClickListener() {
      @Override public void onClick(View v) {
        decryptText();
      }
    });
  }

  @RequiresApi(api = Build.VERSION_CODES.M) private void encryptText() {
    try {
      final String encryptedText =
          securityHelper.encrypt(ALIAS, edTextToEncrypt.getText().toString());
      tvEncryptedText.setText(encryptedText);

      /****************************************************************************************************
       * Store the following values in the local db / preference.                                         *
       * 1.ALIAS // String                                                                                *
       * 2.securityHelper.getEncryption() // byte[]                                                       *
       * 3.securityHelper.getIv() // byte []                                                              *
       * These above three values are needed to get back the plain text.So persist in the db / preference.*
       *                                                                                                  *
       ****************************************************************************************************/

    } catch (InvalidAlgorithmParameterException | SignatureException | IllegalBlockSizeException | BadPaddingException | UnrecoverableEntryException | NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException | IOException | NoSuchPaddingException | InvalidKeyException e) {
      Log.e(TAG, "Encrypt" + e.getMessage(), e);
    }
  }

  private void decryptText() {
    try {
      tvDecryptedText.setText(
          securityHelper.decrypt(ALIAS, securityHelper.getEncryption(), securityHelper.getIv()));
    } catch (CertificateException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | UnrecoverableEntryException | NoSuchAlgorithmException | KeyStoreException | NoSuchPaddingException | NoSuchProviderException | IOException | InvalidKeyException e) {
      Log.e(TAG, "Decrypt" + e.getMessage(), e);
    }
  }
}
