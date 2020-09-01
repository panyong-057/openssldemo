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
        String str = "first blood";
        String s;
        try {
            byte[] bytes = stringFromJNI(str.getBytes());
            s = HexTest.byteArrToHex(bytes);
            Log.e("chris jni", s);
            tv.setText(s);
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");
            byte[] btArr = md5Digest.digest(str.getBytes());
            s = HexTest.byteArrToHex(btArr);
            Log.e("chris java", s);


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
    native byte[] stringFromJNI(byte[] clearText);
}
