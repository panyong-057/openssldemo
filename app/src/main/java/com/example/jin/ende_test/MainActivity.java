package com.example.jin.ende_test;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.security.MessageDigest;
import java.util.Arrays;

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
        String str = "zi lao hu";
        String s;
        try {
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");
            byte[] btArr = md5Digest.digest(str.getBytes());
            s = HexTest.byteArrToHex(btArr);
            tv.setText(s);
            Log.e("chris md5 java", s);


            //jni md5
            byte[] bytes = getJniMd5(str.getBytes());
            s = HexTest.byteArrToHex(bytes);
            Log.e("chris md5 jni", s);


            //jni base64
            Log.e("chris base64 jni",   getJniBase64(str));


        } catch (Exception e) {
            e.printStackTrace();
        }

        //System.arraycopy();
        //Arrays.CopyOf();
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    native byte[] getJniMd5(byte[] clearText);
    native String getJniBase64(String clearText);
}
