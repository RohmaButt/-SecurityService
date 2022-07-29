using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Afiniti.GRM.SecurityService
{
    public sealed class EncryptionClass
    {
        private static string sFlag = ConfigurationManager.AppSettings["EnableEncryption"];

        public static String Encrypt_Decrypt(String pText, Boolean pEncrypt)
        {
            if (sFlag.Equals("0")) { return pText; }

            return Encrypt_Decrypt(pText, ConfigurationManager.AppSettings["Org"], ConfigurationManager.AppSettings["Org"], pEncrypt);
        }

        public static String Encrypt_Decrypt(String pText, string pPhrase, string pPh2, Boolean pEncrypt)
        {
            if (sFlag.Equals("0")) { return pText; }

            return Encrypt_Decrypt(pText, pPhrase, pPh2, 1, 128, pEncrypt);
        }

        private static String Encrypt_Decrypt(String pText, String pPhrase, String pSalt, Int16 pIterations, Int32 pKeySize, Boolean pEncrypt)
        {
            Byte[] initVector = Encoding.ASCII.GetBytes("ENCRYPTIONVECTOR");
            Byte[] saltValue = Encoding.ASCII.GetBytes(pSalt);
            System.Text.Encoding enc = System.Text.Encoding.ASCII;

            Rfc2898DeriveBytes bPassword = new Rfc2898DeriveBytes(pPhrase, saltValue, pIterations);
            Byte[] keyBytes = bPassword.GetBytes(pKeySize / 8);

            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;

            if (pEncrypt)
            {
                Byte[] sText = Encoding.Default.GetBytes(pText);
                ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVector);
                System.IO.MemoryStream mStream = new System.IO.MemoryStream();
                CryptoStream cryptStream = new CryptoStream(mStream, encryptor, CryptoStreamMode.Write);

                cryptStream.Write(sText, 0, sText.Length);
                cryptStream.FlushFinalBlock();

                Byte[] cipherText = mStream.ToArray();
                mStream.Close();
                cryptStream.Close();

                String rText = Convert.ToBase64String(cipherText);
                return rText;
            }
            else
            {
                Byte[] sText = Convert.FromBase64String(pText);
                ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVector);
                System.IO.MemoryStream mStream = new System.IO.MemoryStream(sText);
                CryptoStream cryptStream = new CryptoStream(mStream, decryptor, CryptoStreamMode.Read);

                Byte[] plainText = new Byte[sText.Length];
                Int32 decByteCount = cryptStream.Read(plainText, 0, plainText.Length);

                mStream.Close();
                cryptStream.Close();

                String rText = Encoding.Default.GetString(plainText, 0, decByteCount);
                return rText;
            }
        }
    }
}