package com.github.sharkphin.dca;

import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleObject;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;
import com.google.appinventor.components.runtime.EventDispatcher;
import com.google.appinventor.components.runtime.util.YailList;

import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.os.Build.VERSION;
import android.os.Build;
import android.text.Html;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import org.json.JSONObject;
import java.io.UnsupportedEncodingException;
import java.lang.Math;
import java.lang.String;
import java.lang.StringBuilder;
import java.security.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

@DesignerComponent(
  androidMinSdk = 21,
  category = ComponentCategory.EXTENSION,
  description = "The DCA extension, short for Discourse Community Authentication, will let you generate an API key for any community based on Discourse!",
  helpUrl = "https://github.com/Sharkphin/DCA/README",
  iconName = "images/extension.png",
  nonVisible = true,
  version = 1,
  versionName = "1.0.0"
)
@SimpleObject(external = true)
public class DCA extends AndroidNonvisibleComponent {
  protected Context context;
  protected PublicKey publicKey;
  protected PrivateKey privateKey;
  protected final List isVisible = new ArrayList<>();
  protected final List<AlertDialog> authDialogs = new ArrayList<AlertDialog>();

  public DCA(ComponentContainer container) {
    super(container.$form());
    this.context = container.$context();
    
    try {
      GenerateKeys();
      isVisible.add("false");
    } catch (NoSuchAlgorithmException e) {}
  }

  protected void GenerateKeys() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024);

    KeyPair keyPair = generator.generateKeyPair();
    publicKey = keyPair.getPublic();
    privateKey = keyPair.getPrivate();

    String basePublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    String basePrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
  }

  @SimpleFunction
  public void Authenticate(final String base, final YailList scopes) throws NoSuchPaddingException, UnsupportedEncodingException {
    if (scopes.size() != 0) {
      final String[] acceptedScopes = new String[]{
        "message_bus",
        "one_time_password",
        "read",
        "session_info",
        "write"
      };

      boolean hasUnacceptableScope = false;

      // Basic Info
      String conjointUrl = base;
      conjointUrl += "/user-api-key/new?auth_redirect=discourseforum%3A%2F%2Fcallback";
      conjointUrl += "&application_name=";
      conjointUrl += context.getPackageManager().getApplicationLabel(context.getApplicationInfo());

      double clientId = Math.random() * (999999 - 111111 + 1) + 111111;
      conjointUrl += "&client_id=" + (int) clientId;

      String structuredScopes = "";

      for (String scope : scopes.toStringArray()) {
        if (Arrays.asList(acceptedScopes).contains(scope)) {
          int position = scopes.indexOf(scope);
          int size = scopes.size();

          structuredScopes += (position == size ? scope : scope + "%2C");
        } else {
          hasUnacceptableScope = true;
          break;
        }
      }

      conjointUrl += "&scopes=" + structuredScopes;

      conjointUrl += "&public_key=-----BEGIN%20PUBLIC%20KEY-----%0A";
      conjointUrl += URLEncoder.encode(Base64.getEncoder().encodeToString(publicKey.getEncoded()), "UTF8");
      conjointUrl += "%0A-----END%20PUBLIC%20KEY-----%0A";

      double nonce = Math.random() * (9999999 - 1111111 + 1) + 1111111;
      conjointUrl += "&nonce=" + (int) nonce;

      final String accessConjointUrl = conjointUrl;
      final String baseUrl = base;

      isVisible.set(0, "false");

      if (!hasUnacceptableScope) {
        final AlertDialog authDialog = new AlertDialog.Builder(context).create();

        final WebView webview = new WebView(context);
        webview.getSettings().setBuiltInZoomControls(false);
        webview.getSettings().setJavaScriptEnabled(true);
        webview.getSettings().setUserAgentString(webview.getSettings().getUserAgentString().replace("; wv", ""));
        webview.setFocusable(true);

        webview.setWebViewClient(new WebViewClient() {
          @Override
          public void onPageFinished(WebView view, String url) {
            if (url.contains("/user-api-key/new?auth_redirect=discourseforum%3A%2F%2Fcallback")) {
              isVisible.set(0, "check");
              
              for (AlertDialog dialog : authDialogs) {
                dialog.dismiss();
                authDialogs.remove(authDialogs.indexOf(dialog));
              }

              authDialog.setTitle("Grant application access?");

              final StringBuilder scopeMessage = new StringBuilder();
              for (String scope : scopes.toStringArray()) {
                if (Arrays.asList(acceptedScopes).contains(scope)) {
                  int position = scopes.indexOf(scope);
                  int size = scopes.size();

                  String addition = "";
                  if (scope == "message_bus") {
                    addition = "- Live updates";
                  } else if (scope == "one_time_password") {
                    addition = "- Create a one-time password";
                  } else if (scope == "read") {
                    addition = "- Read all";
                  } else if (scope == "session_info") {
                    addition = "- Read profile information";
                  } else if (scope == "write") {
                    addition = "- Write all";
                  }

                  if (position != size) {
                    scopeMessage.append(addition + "<br>");
                  } else {
                    scopeMessage.append(addition);
                  }
                }
              }

              final String applicationName = "<b>" + context.getPackageManager().getApplicationLabel(context.getApplicationInfo()).toString() + "</b>";

              authDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
                @Override
                public void onCancel(DialogInterface dialog) {
                  OnDenied();
                }
              });

              authDialog.setButton(DialogInterface.BUTTON_POSITIVE, "GRANT", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                  if (which == DialogInterface.BUTTON_POSITIVE) {
                    webview.evaluateJavascript("(() => { document.getElementsByName('commit')[0].click(); return 'true'; })()", new ValueCallback() {
                      @Override
                      public void onReceiveValue(Object value) {}
                    });
                  }
                }
              });

              authDialog.setButton(DialogInterface.BUTTON_NEGATIVE, "DENY", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                  if (which == DialogInterface.BUTTON_NEGATIVE) {
                    dialog.cancel();
                    isVisible.set(0, "false");
                  }
                }
              });

              webview.evaluateJavascript("(() => { return document.getElementsByTagName('title')[0].text; })()", new ValueCallback() {
                @Override
                public void onReceiveValue(Object value) {
                  if (Build.VERSION.SDK_INT >= 24) {
                    authDialog.setMessage(Html.fromHtml(applicationName + " wants access to your <b>" + value.toString().replace("\"", "") + "</b> account with the specified permissions.<br><br>" + scopeMessage.toString(), Html.FROM_HTML_MODE_COMPACT));
                  } else {
                    authDialog.setMessage(Html.fromHtml(applicationName + " wants access to your <b>" + value.toString().replace("\"", "") + "</b> account with the specified permissions.<br><br>" + scopeMessage.toString()));
                  }

                  authDialog.show();
                  authDialogs.add(authDialog);
                }
              });
            } else if (url.contains("auth.kodular.io") || url.contains("/login") || url.contains("accounts.google.com") || url.contains("github.com") || url.contains("facebook.com")) {
              if (isVisible.get(0) == "false") {
                authDialog.setView(webview);
                authDialog.show();
                authDialogs.add(authDialog);
                isVisible.set(0, "true");
              } else if (isVisible.get(0) == "check") {
                for (AlertDialog dialog : authDialogs) {
                  dialog.dismiss();
                  authDialogs.remove(authDialogs.indexOf(dialog));
                }
              }
            }
          }

          @Override
          public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (url.contains("discourseforum://callback")) {
              authDialog.dismiss();
              isVisible.set(0, "false");

              try {
                OnAuthenticated(DecryptPayload(url));
              } catch (NoSuchPaddingException e) {}
              catch(NoSuchAlgorithmException e) {}
              catch(InvalidKeyException e) {}
              catch(BadPaddingException e) {}
              catch(IllegalBlockSizeException e) {}
              catch(UnsupportedEncodingException e) {}
            } else if (url.contains("/user-api-key/new?auth_redirect=discourseforum%3A%2F%2Fcallback")) {
              if (authDialog.isShowing()) {
                isVisible.set(0, "check");

                try {
                  for (AlertDialog dialog : authDialogs) {
                    dialog.dismiss();
                    authDialogs.remove(authDialogs.indexOf(dialog));
                  }
                  Authenticate(base, scopes);
                } catch (NoSuchPaddingException e) {}
                catch(UnsupportedEncodingException e) {}

                return true;
              }
            } else if (url.contains("auth.kodular.io") || url.contains("/login") || url.contains("accounts.google.com") || url.contains("github.com") || url.contains("facebook.com")) {
              if (isVisible.get(0) == "false" && !authDialog.isShowing()) {
                authDialog.setView(webview);
                authDialog.show();
                authDialogs.add(authDialog);
                isVisible.set(0, "true");
              } else if (isVisible.get(0) == "check") {
                for (AlertDialog dialog : authDialogs) {
                  dialog.dismiss();
                  authDialogs.remove(authDialogs.indexOf(dialog));
                }
                return true;
              }
            } else {
              return true;
            }

            return false;
          }
        });

        webview.loadUrl(accessConjointUrl);
      }
    }
  }

  @SimpleEvent
  public void OnAuthenticated(String key) {
    EventDispatcher.dispatchEvent(this, "OnAuthenticated", key);
  }

  @SimpleEvent
  public void OnDenied() {
    EventDispatcher.dispatchEvent(this, "OnDenied");
  }

  protected String DecryptPayload(String payload) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
    if (payload.contains("discourseforum://callback?payload=")) {
      String step1 = payload.replace("discourseforum://callback?payload=", "");
      String step2 = step1.split("&oneTimePassword")[0].toString();
      String step3 = URLDecoder.decode(step2, "UTF8");
      String step4 = step3.replace("\n", "");

      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.DECRYPT_MODE, privateKey);

      String baseResult = new String(cipher.doFinal(Base64.getDecoder().decode(step4.getBytes())));
      JSONObject jsonResult = new JSONObject(baseResult);

      return (jsonResult.has("key") ? jsonResult.getString("key") : "");
    }

    return "";
  }
}