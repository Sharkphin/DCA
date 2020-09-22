package com.github.sharkphin.dca;

import com.google.appinventor.components.runtime.Form;
import com.google.appinventor.components.runtime.util.YailList;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import java.io.UnsupportedEncodingException;
import java.security.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.github.sharkphin.dca.DCA;

public class AuthActivity {
  public static DCA instance;
  public static WebView savedWebview;
  public static YailList registeredScopes;

  public AuthActivity() {
    super();
  }

  public void startAuthorization(Form activity, String baseUrl, Context context, DCA dca, YailList scopes, String url, WebView webview) {
    instance = dca;
    savedWebview = webview;
    registeredScopes = scopes;

    Intent i = new Intent(context, IntentActivity.class);
    i.putExtra("BASE", baseUrl);

    activity.startActivity(i);
  }

  public static class IntentActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
      super.onCreate(savedInstanceState);

      savedWebview.setWebViewClient(new WebViewClient() {
        @Override
        public void onPageFinished(WebView view, String url) {
          if (url != getIntent().getStringExtra("BASE") || !url.contains("auth.kodular.io") || !url.contains("/login") || !url.contains("accounts.google.com") || !url.contains("github.com") || !url.contains("facebook.com") || !url.contains("twitter.com")) {
            return true;
          }
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
          if (url.contains("/user-api-key/new?auth_redirect=discourseforum%3A%2F%2Fcallback")) {
            try {
              instance.Authenticate(getIntent().getStringExtra("BASE"), registeredScopes);
              finish();
            } catch(NoSuchPaddingException e) {}
            catch (UnsupportedEncodingException e) {}
          } else if (url != getIntent().getStringExtra("BASE") || !url.contains("auth.kodular.io") || !url.contains("/login") || !url.contains("accounts.google.com") || !url.contains("github.com") || !url.contains("facebook.com") || !url.contains("twitter.com")) {
            return true;
          }

          return false;
        }
      });

      this.setContentView(savedWebview);
    }
  }
}