using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace OAuth
{
	public class OAuthBase
	{
		/// <summary>
		/// プロトコルによってサポートされているハッシュアルゴリズム
		/// </summary>
		public enum SignatureTypes
		{
			HMACSHA1,
			PLAINTEXT,
			RSASHA1
		}

		/// <summary>
		/// クエリパラメータを表す
		/// </summary>
		protected class QueryParameter
		{
			private string name = null;
			private string value = null;

			public QueryParameter(string name, string value)
			{
				this.name = name;
				this.value = value;
			}

			public string Name
			{
				get { return name; }
			}

			public string Value
			{
				get { return value; }
			}
		}

		/// <summary>
		/// クエリパラメータの比較
		/// </summary>
		protected class QueryParameterComparer : IComparer<QueryParameter>
		{
			public int Compare(QueryParameter x, QueryParameter y)
			{
				if(x.Name == y.Name)
				{
					return string.Compare(x.Value, y.Value);
				}
				else
				{
					return string.Compare(x.Name, y.Name);
				}
			}
		}

		protected const string OAuthVersion = "1.0";
		protected const string OAuthParameterPrefix = "oauth_";

		protected const string OAuthConsumerKeyKey = "oauth_consumer_key";

		protected const string OAuthCallbackKey = "oauth_callback";
		protected const string OAuthVersionKey = "oauth_version";
		protected const string OAuthSignatureMethodKey = "oauth_signature_method";
		protected const string OAuthSignatureKey = "oauth_signature";
		protected const string OAuthTimestampKey = "oauth_timestamp";
		protected const string OAuthNonceKey = "oauth_nonce";
		protected const string OAuthTokenKey = "oauth_token";
		protected const string OAuthTokenSecretKey = "oauth_token_secret";

		protected const string HMACSHA1SignatureType = "HMAC-SHA1";
		protected const string PlainTextSignatureType = "PLAINTEXT";
		protected const string RSASHA1SignatureType = "RSA-SHA1";

		protected Random random = new Random();

		protected string unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

		/// <summary>
		/// 与えられたデータをハッシュアルゴリズムを用いて計算し、base64文字列にして返す
		/// </summary>
		/// <param name="hashAlgorithm">ハッシュアルゴリズム</param>
		/// <param name="data">データ</param>
		/// <returns>Base64エンコードされたハッシュ値</returns>
		private string ComputeHash(HashAlgorithm hashAlgorithm, string data)
		{
			if(hashAlgorithm == null)
			{
				throw new ArgumentNullException("hashAlgorithm");
			}

			if(string.IsNullOrEmpty(data))
			{
				throw new ArgumentNullException("data");
			}

			byte[] dataBuffer = System.Text.Encoding.ASCII.GetBytes(data);
			byte[] hashBytes = hashAlgorithm.ComputeHash(dataBuffer);

			return Convert.ToBase64String(hashBytes);
		}

		/// <summary>
		/// 各クエリパラメータをリストに格納
		/// </summary>
		/// <param name="parameters">クエリ文字列</param>
		/// <returns>リスト化されたクエリ文字列</returns>
		private List<QueryParameter> GetQueryParameters(string parameters)
		{
			if(parameters.StartsWith("?"))
			{
				parameters = parameters.Remove(0, 1);
			}

			List<QueryParameter> result = new List<QueryParameter>();

			if(!string.IsNullOrEmpty(parameters))
			{
				string[] p = parameters.Split('&');
				foreach(string s in p)
				{
					if(!string.IsNullOrEmpty(s) && !s.StartsWith(OAuthParameterPrefix))
					{
						if(s.IndexOf('=') > -1)
						{
							string[] temp = s.Split('=');
							result.Add(new QueryParameter(temp[0], temp[1]));
						}
						else
						{
							result.Add(new QueryParameter(s, string.Empty));
						}
					}
				}
			}

			return result;
		}

		/// <summary>
		/// OAuth形式URLエンコード
		/// </summary>
		/// <param name="value">エンコードするURL</param>
		/// <returns>エンコードされたURL</returns>
		protected string UrlEncode(string value)
		{
			StringBuilder result = new StringBuilder();

			foreach(char symbol in value)
			{
				if(unreservedChars.IndexOf(symbol) != -1)
				{
					result.Append(symbol);
				}
				else
				{
					result.Append('%' + String.Format("{0:X2}", (int)symbol));
				}
			}

			return result.ToString();
		}

		/// <summary>
		/// リクエストパラメータを生成する
		/// </summary>
		/// <param name="parameters">ソート済みのパラメータリスト</param>
		/// <returns>パラメータ文字列</returns>
		protected string NormalizeRequestParameters(IList<QueryParameter> parameters)
		{
			StringBuilder sb = new StringBuilder();
			QueryParameter p = null;
			for(int i = 0; i < parameters.Count; i++)
			{
				p = parameters[i];
				sb.AppendFormat("{0}={1}", p.Name, p.Value);

				if(i < parameters.Count - 1)
				{
					sb.Append("&");
				}
			}

			return sb.ToString();
		}

		/// <summary>
		/// oauth_signature生成に必要なダイジェスト(基盤)を生成
		/// </summary>
		/// <param name="url">URL</param>
		/// <param name="consumerKey">ConsumerKey</param>
		/// <param name="token">リクエストトークン</param>
		/// <param name="tokenSecret">リクエストトークンシークレット</param>
		/// <param name="httpMethod">HTTPプロトコルのリクエスト</param>
		/// <param name="signatureType">ハッシュアルゴリズム<see cref="OAuthBase.SignatureTypes">OAuthBase.SignatureTypes</see>.</param>
		/// <returns>The signature base</returns>
		public string GenerateSignatureBase(Uri url, string consumerKey, string token, string tokenSecret, string httpMethod, string timeStamp, string nonce, string signatureType, out string normalizedUrl, out string normalizedRequestParameters)
		{
			if(token == null)
			{
				token = string.Empty;
			}

			if(tokenSecret == null)
			{
				tokenSecret = string.Empty;
			}

			if(string.IsNullOrEmpty(consumerKey))
			{
				throw new ArgumentNullException("consumerKey");
			}

			if(string.IsNullOrEmpty(httpMethod))
			{
				throw new ArgumentNullException("httpMethod");
			}

			if(string.IsNullOrEmpty(signatureType))
			{
				throw new ArgumentNullException("signatureType");
			}

			normalizedUrl = null;
			normalizedRequestParameters = null;

			List<QueryParameter> parameters = GetQueryParameters(url.Query);
			parameters.Add(new QueryParameter(OAuthVersionKey, OAuthVersion));
			parameters.Add(new QueryParameter(OAuthNonceKey, nonce));
			parameters.Add(new QueryParameter(OAuthTimestampKey, timeStamp));
			parameters.Add(new QueryParameter(OAuthSignatureMethodKey, signatureType));
			parameters.Add(new QueryParameter(OAuthConsumerKeyKey, consumerKey));

			if(!string.IsNullOrEmpty(token))
			{
				parameters.Add(new QueryParameter(OAuthTokenKey, token));
			}

			parameters.Sort(new QueryParameterComparer());

			normalizedUrl = string.Format("{0}://{1}", url.Scheme, url.Host);
			if(!((url.Scheme == "http" && url.Port == 80) || (url.Scheme == "https" && url.Port == 443)))
			{
				normalizedUrl += ":" + url.Port;
			}
			normalizedUrl += url.AbsolutePath;
			normalizedRequestParameters = NormalizeRequestParameters(parameters);

			StringBuilder signatureBase = new StringBuilder();
			signatureBase.AppendFormat("{0}&", httpMethod.ToUpper());
			signatureBase.AppendFormat("{0}&", UrlEncode(normalizedUrl));
			signatureBase.AppendFormat("{0}", UrlEncode(normalizedRequestParameters));

			return signatureBase.ToString();
		}

		/// <summary>
		/// ハッシュアルゴリズムを用いたシグネチャを生成
		/// </summary>
		/// <param name="signatureBase">ハッシュアルゴリズム適用対象</param>
		/// <param name="hash">ハッシュアルゴリズム</param>
		/// <returns>Base64エンコードされたダイジェスト</returns>
		public string GenerateSignatureUsingHash(string signatureBase, HashAlgorithm hash)
		{
			return ComputeHash(hash, signatureBase);
		}

		/// <summary>
		/// シグネチャを生成する
		/// </summary>
		/// <param name="url">URL</param>
		/// <param name="consumerKey">ConsumerKey</param>
		/// <param name="consumerSecret">ConsumerSecret</param>
		/// <param name="token">アクセストークン</param>
		/// <param name="tokenSecret">アクセストークンシークレット</param>
		/// <param name="httpMethod">HTTPプロトコルのリクエスト</param>
		/// <param name="timeStamp">タイムスタンプ</param>
		/// <param name="nonce">ノンス</param>
		/// <param name="normalizedUrl">シグネチャの生成に用いたURL</param>
		/// <param name="normalizedRequestParameters">シグネチャの生成に用いたリクエストパラメータ</param>
		/// <param name="signatureType">ハッシュアルゴリズム</param>
		/// <returns></returns>
		public string GenerateSignature(Uri url, string consumerKey, string consumerSecret, string token,
																		string tokenSecret, string httpMethod, string timeStamp, string nonce,
																		out string normalizedUrl, out string normalizedRequestParameters,
																		SignatureTypes signatureType = SignatureTypes.HMACSHA1)
		{
			normalizedUrl = null;
			normalizedRequestParameters = null;

			switch(signatureType)
			{
				case SignatureTypes.PLAINTEXT:
					return HttpUtility.UrlEncode(string.Format("{0}&{1}", consumerSecret, tokenSecret));

				case SignatureTypes.HMACSHA1:
					string signatureBase = GenerateSignatureBase(url, consumerKey, token, tokenSecret, httpMethod, timeStamp, nonce, HMACSHA1SignatureType, out normalizedUrl, out normalizedRequestParameters);

					HMACSHA1 hmacsha1 = new HMACSHA1();
					hmacsha1.Key = Encoding.ASCII.GetBytes(string.Format("{0}&{1}", UrlEncode(consumerSecret), string.IsNullOrEmpty(tokenSecret) ? "" : UrlEncode(tokenSecret)));

					return GenerateSignatureUsingHash(signatureBase, hmacsha1);

				case SignatureTypes.RSASHA1:
					throw new NotImplementedException();
				default:
					throw new ArgumentException("Unknown signature type", "signatureType");
			}
		}

		/// <summary>
		/// タイムスタンプの生成
		/// </summary>
		/// <returns>世界協定時刻-UNIX時間</returns>
		public virtual string GenerateTimeStamp()
		{
			TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			return Convert.ToInt64(ts.TotalSeconds).ToString();
		}

		/// <summary>
		/// ノンス生成
		/// </summary>
		/// <returns>12340-9999999の乱数値</returns>
		public virtual string GenerateNonce()
		{
			return random.Next(123400, 9999999).ToString();
		}
	}
}