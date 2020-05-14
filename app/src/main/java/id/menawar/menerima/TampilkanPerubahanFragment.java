package id.menawar.menerima;

import android.annotation.TargetApi;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatDialogFragment;

public class TampilkanPerubahanFragment extends AppCompatDialogFragment {
    public TampilkanPerubahanFragment() {
    }

    public static TampilkanPerubahanFragment newInstance() {
        return new TampilkanPerubahanFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.situs, container);
    }

    WebView wvPage1;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        wvPage1 = view.findViewById(R.id.wvPage1);
        wvPage1.loadUrl(getString(R.string.penawaran));
        WebSettings settings = wvPage1.getSettings();
        settings.setJavaScriptEnabled(true);
        wvPage1.setWebViewClient(new MyWebViewClient());
        wvPage1.requestFocus();
    }

    private class MyWebViewClient extends WebViewClient {
        @SuppressWarnings("deprecation")
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            return true;
        }

        @TargetApi(Build.VERSION_CODES.N)
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            view.loadUrl(request.getUrl().toString());
            return true;
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            Handler lHandler = new Handler();
            lHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    wvPage1.scrollTo(0, 1000000000);
                }
            }, 200);
        }
    }
}