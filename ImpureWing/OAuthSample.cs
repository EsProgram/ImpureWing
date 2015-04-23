using OAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace TwitterClient
{
  internal class Program
  {
    private static readonly string CONSUMER_KEY = "EIFYUbIF5ZsoJipVv9FMsA";
    private static readonly string CONSUMER_SECRET = "J1W1fGUNZURRFFDROuw8mxKOMPSZZdCfQ6rwbrg6Q";

    private static readonly string REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token";
    private static readonly string AUTHORIZE_URL = "https://api.twitter.com/oauth/authorize";
    private static readonly string ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token";

    private static void Main(string[] args)
    {
      OAuthBase oauth = new OAuthBase();

      // トークン格納用
      Dictionary<string, string> tokens = new Dictionary<string, string>();

      //---------------------------
      // 0.リクエストトークン取得の前処理
      //---------------------------

      // ランダム文字列の生成
      string nonce = oauth.GenerateNonce();

      // タイムスタンプ（unix時間）
      string timestamp = oauth.GenerateTimeStamp();
      string normalizedUrl, normalizedReqParams;

      Uri reqUrl = new Uri(REQUEST_TOKEN_URL);

      // Consumer_Secretを暗号鍵とした署名の生成
      string signature = oauth.GenerateSignature(reqUrl
                                              , CONSUMER_KEY
                                              , CONSUMER_SECRET
                                              , null
                                              , null
                                              , "GET"
                                              , timestamp
                                              , nonce
                                              , out normalizedUrl
                                              , out normalizedReqParams);

      /// リクエストトークン取得用URL
      string reqTokenUrl = normalizedUrl + "?"
                         + normalizedReqParams
                         + "&oauth_signature=" + signature;

      try
      {
        //---------------------------
        // 1.リクエストトークン取得
        //---------------------------

        WebClient client = new WebClient();
        Stream st = client.OpenRead(reqTokenUrl);//サーバエラーで例外が投げられることがある
        StreamReader sr = new StreamReader(st, Encoding.GetEncoding("Shift_JIS"));

        tokens = convertToTokenForOauth(sr.ReadToEnd());

        // 取得したリクエストトークン
        Console.WriteLine(
              "(request)oauth_token        = {0}\r\n"
            + "(requrst)oauth_token_secret = {1}\r\n"
            , tokens["oauth_token"]
            , tokens["oauth_token_secret"]
             );

        //---------------------------
        // 2.オーサライズ
        //---------------------------

        string authorizeUrl = AUTHORIZE_URL + "?"
                                + "oauth_token=" + tokens["oauth_token"]
                                + "&oauth_token_secret=" + tokens["oauth_token_secret"];

        // ブラウザ起動しPINコードを表示
        System.Diagnostics.Process.Start(authorizeUrl);

        //---------------------------
        // 3.PINコード認証
        //---------------------------

        Console.WriteLine();
        Console.Write("PINコードを入力してください。 >> ");
        string pin = Console.ReadLine();

        //---------------------------
        // 4.アクセストークン取得
        //---------------------------

        // リクエストトークンを加えsignatureを再生成
        signature = oauth.GenerateSignature(reqUrl
                                            , CONSUMER_KEY
                                            , CONSUMER_SECRET
                                            , tokens["oauth_token"]
                                            , tokens["oauth_token_secret"]
                                            , "GET"
                                            , timestamp
                                            , nonce
                                            , out normalizedUrl
                                            , out normalizedReqParams);

        // アクセストークン取得用URL
        string accessTokenUrl = ACCESS_TOKEN_URL + "?"
                                    + normalizedReqParams
                                    + "&oauth_signature=" + signature
                                    + "&oauth_verifier=" + pin;

        st = client.OpenRead(accessTokenUrl);//リモートサーバからエラーが起きた際に例外が投げられる

        sr = new StreamReader(st, Encoding.GetEncoding("Shift_JIS"));

        tokens = convertToTokenForOauth(sr.ReadToEnd());

        // 取得したアクセストークン
        Console.WriteLine(
              "(access)oauth_token         = {0}\r\n"
            + "(access)oauth_token_secret  = {1}\r\n"
            + "user_id                     = {2}\r\n"
            + "screen_name                 = {3}\r\n"
            , tokens["oauth_token"]
            , tokens["oauth_token_secret"]
            , tokens["user_id"]
            , tokens["screen_name"]
             );
      }
      catch(Exception ex)
      {
        // たまに「リモート サーバーがエラーを返しました: (401) 許可されていません」のエラーが返される
        Console.WriteLine(ex.Message);
      }
    }

    /// <summary>
    /// 取得した文字列を分解し、ハッシュテーブルに格納する
    /// </summary>
    /// <param name="data">文字列</param>
    /// <param name="oauthKey">ハッシュテーブル</param>
    static private Dictionary<string, string> convertToTokenForOauth(string data)
    {
      Dictionary<string, string> oauthKey = new Dictionary<string, string>();

      foreach(string s in data.Split('&'))
      {
        oauthKey.Add(s.Substring(0, s.IndexOf("="))
            , s.Substring(s.IndexOf("=") + 1));
      }

      return oauthKey;
    }
  }
}
