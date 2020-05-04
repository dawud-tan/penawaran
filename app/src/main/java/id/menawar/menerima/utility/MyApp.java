package id.menawar.menerima.utility;

import android.app.Application;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.URLConnection;
import java.security.Security;

/**
 * Created by dawud_tan on 10/8/17.
 */
public class MyApp extends Application {
    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception ex) {
            Log.e(Application.class.getName(), ex.getMessage());
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        URLConnection.setContentHandlerFactory(mimetype -> {
            if (mimetype.startsWith("multipart/signed")) {
                return new MultipartSigned();
            }
            return null;
        });
    }
}