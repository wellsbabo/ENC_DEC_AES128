using System.Security.Cryptography;
using System.Text;

public class AESHelper
{
    private static string ToUrlSafeBase64String(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static byte[] FromUrlSafeBase64String(string input)
    {
        string base64 = input
            .Replace('-', '+')
            .Replace('_', '/');

        switch (input.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        return Convert.FromBase64String(base64);
    }

    public static string Encrypt(string plainText, string key)
    {
        // AES 키 길이는 128비트 (16바이트)여야 합니다.
        // 주어진 키의 길이가 16바이트가 되도록 맞춰줍니다.
        byte[] keyBytes = new byte[16];
        byte[] passwordBytes = Encoding.UTF8.GetBytes(key);
        Array.Copy(passwordBytes, keyBytes, Math.Min(keyBytes.Length, passwordBytes.Length));

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = keyBytes;
            aesAlg.Mode = CipherMode.ECB;
            aesAlg.Padding = PaddingMode.PKCS7;

            // 암호화를 위해 ICryptoTransform 객체 생성
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // 암호화된 데이터를 저장할 버퍼 생성
            byte[] encryptedBytes;
            using (var msEncrypt = new System.IO.MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    csEncrypt.FlushFinalBlock();
                    encryptedBytes = msEncrypt.ToArray();
                }
            }

            // Base64 문자열로 반환
            return ToUrlSafeBase64String(encryptedBytes);
        }       
    }


    public static string Decrypt(string encryptedText, string key)
    {
        // AES 키 길이는 128비트 (16바이트)여야 합니다.
        // 주어진 키의 길이가 16바이트가 되도록 맞춰줍니다.
        byte[] keyBytes = new byte[16];
        byte[] passwordBytes = Encoding.UTF8.GetBytes(key);
        Array.Copy(passwordBytes, keyBytes, Math.Min(keyBytes.Length, passwordBytes.Length));

        byte[] encryptedBytes = FromUrlSafeBase64String(encryptedText);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = keyBytes;
            aesAlg.Mode = CipherMode.ECB;
            aesAlg.Padding = PaddingMode.PKCS7;

            // 복호화를 위해 ICryptoTransform 객체 생성
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // 복호화된 데이터를 저장할 버퍼 생성
            using (var msDecrypt = new System.IO.MemoryStream(encryptedBytes))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new System.IO.StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        string plainText = "TEST1234#$%^성공";
        string key = "ABCDEFG1234F!#%^";

        // 문자열 암호화
        string encryptedText = AESHelper.Encrypt(plainText, key);
        Console.WriteLine("암호화된 문자열: " + encryptedText);

        // 문자열 복호화
        string decryptedText = AESHelper.Decrypt(encryptedText, key);
        Console.WriteLine("복호화된 문자열: " + decryptedText);
    }
}
