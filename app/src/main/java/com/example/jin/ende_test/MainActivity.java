package com.example.jin.ende_test;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;
import java.security.MessageDigest;
public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);


        try {
            String md5_str = " zi lao hu";
            String md5_encode;
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");
            byte[] btArr = md5Digest.digest(md5_str.getBytes());
            md5_encode = HexTest.byteArrToHex(btArr);
            tv.setText(md5_encode);
            Log.e(" md5 java", md5_encode);


            //jni md5
            byte[] bytes = getJniMd5(md5_str.getBytes());
            md5_encode = HexTest.byteArrToHex(bytes);
            Log.e(" md5 jni", md5_encode);
          //  byte[] encodeBytes = org.apache.commons.codec.binary.Base64.encodeBase64(str.getBytes());
            //Base64.toBase64String(str.getBytes());


            String base64_str = " biu biu biu";
            String strBase64 = Base64.encodeToString(base64_str.getBytes(), Base64.DEFAULT);


            Log.e("base64 java",  strBase64);

            String base64Encode = getJniBase64(base64_str);
            Log.e("base64 jni",  base64Encode);


        } catch (Exception e) {
            e.printStackTrace();
        }

        //System.arraycopy();
        //Arrays.CopyOf();

        finish();
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    native byte[] getJniMd5(byte[] clearText);
    native String getJniBase64(String clearText);
    native String getJniRSA(String clearText);
    native String getJniAES(String clearText);
    native String getJniSM2(String clearText);
    native String getJniSM3(String clearText);
    native String getJniSM4(String clearText);
}
