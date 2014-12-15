using CoreTweet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ImpureWing
{
	internal class Program
	{
		private const string ACCESS_FILE = "access.txt";

		private static void Main(string[] args)
		{
			var tokens = StartUp();
		}

		private static Tokens StartUp()
		{
			Dictionary<string, string> token_data = new Dictionary<string, string>();
			if(!File.Exists(ACCESS_FILE))
			{
				var session = OAuth.Authorize("_consumerkey_", "_consumersecret_");
				Process.Start(session.AuthorizeUri.AbsoluteUri);
				Console.Write("PIN_CODE:");
				var pin_code = Console.ReadLine();
				var token = OAuth.GetTokens(session, pin_code);
				using(TextWriter sw = new StreamWriter(ACCESS_FILE))
				{
					sw.WriteLine("ConsumerKey:" + session.ConsumerKey);
					sw.WriteLine("ConsumerSecret:" + session.ConsumerSecret);
					sw.WriteLine("AccessToken:" + token.AccessToken);
					sw.WriteLine("AccessTokenSecret:" + token.AccessTokenSecret);
				}
			}

			using(TextReader r = new StreamReader(ACCESS_FILE))
			{
				for(int i = 0; i < 4; ++i)
				{
					var data = r.ReadLine().Split(':');
					token_data.Add(data[0], data[1]);
				}
			}

			return Tokens.Create(token_data["ConsumerKey"], token_data["ConsumerSecret"],
													 token_data["AccessToken"], token_data["AccessTokenSecret"]);
		}
	}
}