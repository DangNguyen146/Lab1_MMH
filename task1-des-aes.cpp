#include <iostream>
using std::cerr;
using std::cout;
using std::endl;
using std::getline;
using std::wcin;
using std::wcout;

#include <stdlib.h>

#include <string>
using std::string;
using std::wstring;

#include "cryptopp/osrng.h" //generate random number
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h" //cyptoopp byte (distinguish with c++ byte)
using CryptoPP::SecByteBlock;

#include "cryptopp/des.h"
using CryptoPP::DES;
using CryptoPP::DES_EDE2;
using CryptoPP::DES_EDE3;

#include <cstdlib>
using CryptoPP::byte; //byte cryptoop
using std::exit;

#include "cryptopp/filters.h"
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/xts.h"
using CryptoPP::XTS_Mode;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;
#include "cryptopp/stdafx.h"

#include "cryptopp/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <assert.h>

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <ctime>
#include <codecvt>
/*Vietnamese support*/
// Convert unicode
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* convert string to wstring */
wstring string_to_wstring(const std::string &str);
/* convert wstring to string */
string wstring_to_string(const std::wstring &str);

void option_DESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_2TDESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_3TDESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);

void option_AESECB(byte key[], wstring wplain, string plain, int keyLength);
void option_AESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESOFB(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESCFB(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESCTR(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESXTS(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESCCM(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESGCM(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);

void option_DESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_2TDESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_3TDESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);

void option_AESECB_time(byte key[], wstring wplain, string plain, int keyLength);
void option_AESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESOFB_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESCFB_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESCTR_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESXTS_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESCCM_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);
void option_AESGCM_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength);

void DisplayResult(double total);

int main()
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    int mode;
    wcout << L"|------Chọn loại------|\n|- 1. DES ------------|\n|- 2. AES ------------|\nYour select>> ";
    wcin >> mode;
    wcin.ignore();

    int category;
    if (mode == 1)
    {
        wcout << L"|------Chọn loại------|\n|- 1. CBC ------------|\n|- 2. 2CBC ------------|\n|- 3. 3CBC ------------|\nYour select>> ";
    }
    else
    {
        wcout << L"|------Chọn loại------|\n|- 1. ECB ------------|\n|- 2. CBC ------------|\n|- 3. OFB ------------|\n|- 4. CFB ------------|\n|- 5. CTR ------------|\n|- 6. XTS ------------|\n|- 7. CCM ------------|\n|- 8. GCM ------------|\nYour select>> ";
    }
    wcin >> category;
    wcin.ignore();

    int option;
    wcout << L"|-------------------------------------------------------|\n|------------------------WINDOWS------------------------|\n|-------- Mã hóa DES-AES bằng thư viện cryptopp --------|\n|- CASE 1: Key and IV are randomly > AutoSeededRandomPool|\n|- CASE 2: Input Secret Key and IV from screen ---------|\n|- CASE 3: Input Secret Key and IV from file -----------|\n|-------------------------------------------------------|\nYour select>> ";
    wcin >> option;
    wcin.ignore();

    int a = 0;
    double total;
    int keyLength, ivLength;

    if (mode == 1) //DES
    {
        if (category == 1)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[DES::BLOCKSIZE];
            cout << "key length: " << DES::DEFAULT_KEYLENGTH << endl;
            wcout << "block size: " << DES::BLOCKSIZE << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(8 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (8 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(8);
                keyLength = 8;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(8);
                ivLength = 8;
            }
            option_DESCBC(key, iv, wplain, plain, keyLength, ivLength);

            while (a < 10000)
            {
                int start_s = clock();

                option_DESCBC_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 2)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[DES_EDE2::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[DES_EDE2::BLOCKSIZE];

            wcout << "key length: " << DES_EDE2::DEFAULT_KEYLENGTH << endl;
            wcout << "block size: " << DES_EDE2::BLOCKSIZE << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (8 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(8);
                ivLength = 8;
            }
            option_2TDESCBC(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_2TDESCBC_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 3)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[DES_EDE3::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[DES_EDE3::BLOCKSIZE];

            wcout << "key length: " << DES_EDE3::DEFAULT_KEYLENGTH << endl;
            wcout << "block size: " << DES_EDE3::BLOCKSIZE << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (8 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));

                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(24);
                keyLength = 24;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(8);
                ivLength = 8;
            }
            option_3TDESCBC(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_3TDESCBC_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
    }
    if (mode == 2) //AES
    {
        if (category == 1)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];

            wcout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;

            wstring wkey;
            string keyString;

            if (option == 1)
            {
                AutoSeededRandomPool prng;
                prng.GenerateBlock(key, sizeof(key));
                keyLength = sizeof(key);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                keyLength = keyString.length();
            }
            else
            {
                FileSource fs_key("aes_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                ivLength = 16;
            }
            option_AESECB(key, wplain, plain, keyLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESECB_time(key, wplain, plain, keyLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 2)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[AES::BLOCKSIZE];

            wcout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
            wcout << "block size: " << AES::BLOCKSIZE << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(16);
                keyLength = 16;

                //iv
                wcout << L"Nhập iv (16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(16);
                ivLength = 16;

                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(16);
                ivLength = 16;
            }
            option_AESCBC(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESCBC_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 3)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[AES::BLOCKSIZE];

            wcout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
            wcout << "block size: " << AES::BLOCKSIZE << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(16);
                ivLength = 16;
            }
            option_AESOFB(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESOFB_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 4)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[AES::BLOCKSIZE];

            wcout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
            wcout << "block size: " << AES::BLOCKSIZE << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(16);
                ivLength = 16;
            }
            option_AESCFB(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESCFB_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 5)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[AES::BLOCKSIZE];

            wcout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
            wcout << "block size: " << AES::BLOCKSIZE << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(16);
                ivLength = 16;
            }
            option_AESCTR(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESCTR_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 6)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);

            SecByteBlock key(32), iv(16);
            wcout << "key length: " << sizeof(key) << endl;
            wcout << "block size: " << sizeof(iv) << endl;

            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(16);
                ivLength = 16;
            }
            option_AESXTS(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESXTS_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 7)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);
            // Human Readable
            byte key[AES::DEFAULT_KEYLENGTH];
            // memset(key, '4', sizeof(key));
            byte iv[12];
            // memset(iv, '8', sizeof(iv));
            wcout << "key length: " << sizeof(key) << endl;
            wcout << "block size: " << sizeof(iv) << endl;
            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(16);
                ivLength = 16;
            }
            option_AESCCM(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESCCM_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
        if (category == 8)
        {
            string plain;
            wstring wplain;
            wcout << "Please input message: ";
            fflush(stdin);
            getline(wcin, wplain); //byte wstring
            plain = wstring_to_string(wplain);
            //KEY 0000000000000000000000000000000000000000000000000000000000000000
            //IV  000000000000000000000000
            //HDR 00000000000000000000000000000000
            //PTX 00000000000000000000000000000000
            //CTX cea7403d4d606b6e074ec5d3baf39d18
            //TAG ae9b1771dba9cf62b39be017940330b4

            // Test Vector 003
            byte key[32];
            // memset(key, 0, sizeof(key));
            byte iv[12];
            // memset(iv, 0, sizeof(iv));

            wcout << "key length: " << sizeof(key) << endl;
            wcout << "block size: " << sizeof(iv) << endl;
            wstring wkey, wiv;
            string keyString, ivString;

            AutoSeededRandomPool prng;
            if (option == 1)
            {
                prng.GenerateBlock(key, sizeof(key));
                prng.GenerateBlock(iv, sizeof(iv));
                keyLength = sizeof(key);
                ivLength = sizeof(iv);
            }
            else if (option == 2)
            {
                //key
                wcout << L"Nhập key(16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wkey);
                keyString = wstring_to_string(wkey);

                StringSource ss(keyString, false);
                CryptoPP::ArraySink copykey(key, sizeof(key));
                ss.Detach(new Redirector(copykey));
                ss.Pump(sizeof(key));

                //iv
                wcout << L"Nhập iv (16 bytes): ";
                fflush(stdin);
                wcin.ignore();
                getline(wcin, wiv);
                ivString = wstring_to_string(wiv);

                StringSource cc(ivString, false);
                CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                cc.Detach(new Redirector(copyiv));
                cc.Pump(sizeof(key));
                keyLength = keyString.length();
                ivLength = ivString.length();
            }
            else
            {
                FileSource fs_key("des_key.key", false);
                CryptoPP::ArraySink bytes_key(key, sizeof(key));
                fs_key.Detach(new Redirector(bytes_key));
                fs_key.Pump(16);
                keyLength = 16;

                FileSource fs_iv("des_iv.key", false);
                CryptoPP::ArraySink bytes_iv(iv, sizeof(iv));
                fs_iv.Detach(new Redirector(bytes_iv));
                fs_iv.Pump(16);
                ivLength = 16;
            }
            option_AESGCM(key, iv, wplain, plain, keyLength, ivLength);
            while (a < 10000)
            {
                int start_s = clock();

                option_AESGCM_time(key, iv, wplain, plain, keyLength, ivLength);

                int stop_s = clock();
                total += (stop_s - start_s) / double(CLOCKS_PER_SEC) * 1000;
                a++;
            }
            DisplayResult(total);
        }
    }

    std::wcout << "Would you like to exit?";
    std::wcin.get();
    return 0;
}

/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void option_DESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "iv: " << string_to_wstring(encoded) << endl;
    try
    {
        wcout << "plain text: " << wplain << endl;

        CBC_Mode<DES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }

    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    try
    {
        CBC_Mode<DES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_2TDESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    /*********************************\
	\*********************************/

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "iv: " << string_to_wstring(encoded) << endl;

    /*********************************\
	\*********************************/

    try
    {
        wcout << "plain text: " << wplain << endl;

        CBC_Mode<DES_EDE2>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    try
    {
        CBC_Mode<DES_EDE2>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_3TDESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "iv: " << string_to_wstring(encoded) << endl;

    try
    {
        wcout << "plain text: " << wplain << endl;

        CBC_Mode<DES_EDE3>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded	-->OFB
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(              //BIEU DIEN THANH Base64Encoder
                     new StringSink(encoded)) // HexEncoder		//BIEU DIEN THANH Base64Encoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    try
    {
        CBC_Mode<DES_EDE3>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESECB(byte key[], wstring wplain, string plain, int keyLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    try
    {
        wcout << "plain text: " << wplain << endl;

        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, keyLength);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    try
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, keyLength);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESCBC(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "iv: " << string_to_wstring(encoded) << endl;

    try
    {
        wcout << "plain text: " << wplain << endl;

        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    try
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
};
void option_AESOFB(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    string cipher, encoded, recovered;

    /*********************************\
	\*********************************/

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "iv: " << string_to_wstring(encoded) << endl;

    /*********************************\
	\*********************************/

    try
    {
        wcout << "plain text: " << wplain << endl;

        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // OFB mode must not use padding. Specifying
        //  a scheme will result in an exception
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    /*********************************\
	\*********************************/

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    /*********************************\
	\*********************************/

    try
    {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESCFB(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    string cipher, encoded, recovered;

    /*********************************\
	\*********************************/

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "iv: " << string_to_wstring(encoded) << endl;

    /*********************************\
	\*********************************/

    try
    {
        wcout << "plain text: " << wplain << endl;

        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // CFB mode must not use padding. Specifying
        //  a scheme will result in an exception
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    /*********************************\
	\*********************************/

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    /*********************************\
	\*********************************/

    try
    {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESCTR(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "iv: " << string_to_wstring(encoded) << endl;

    /*********************************\
	\*********************************/

    try
    {
        wcout << "plain text: " << wplain << endl;

        CTR_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    try
    {
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESXTS(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    string cipher, encoded, recovered;

    try
    {
        wcout << "plain text: " << wplain << std::endl;

        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as requiredec. ECB and XTS Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plain, true,
                        new StreamTransformationFilter(enc,
                                                       new StringSink(cipher),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                                     // StringSource
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }

    // Pretty print cipher text
    StringSource ss(cipher, true,
                    new HexEncoder(
                        new StringSink(encoded)) // HexEncoder
    );                                           // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << std::endl;

    /*********************************\
\*********************************/

    try
    {
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as requiredec.
        StringSource ss(cipher, true,
                        new StreamTransformationFilter(dec,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                                     // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << std::endl;
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }
}
void option_AESCCM(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{

    //memset( iv, '8', ivLength );
    //string adata="Authenticated";
    //string pdata="Authenticated Encryption";
    //const int TAG_SIZE = 6;

    // Test Vector 003
    // byte key[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    //               0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    // byte iv[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    //              0x17, 0x18, 0x19, 0x1a, 0x1b};

    const byte aa[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};
    string adata = string((const char *)aa, sizeof(aa));

    const byte pa[] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                       0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                       0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    string pdata = string((const char *)pa, sizeof(pa));
    const int TAG_SIZE = 8;

    //CTX e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5
    //TAG 484392fbc1b09951

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/

    try
    {
        CCM<AES, TAG_SIZE>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv, ivLength);
        e.SpecifyDataLengths(adata.size(), pdata.size(), 0);

        AuthenticatedEncryptionFilter ef(e,
                                         new StringSink(cipher)); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data
        ef.ChannelPut("", (const byte *)pdata.data(), pdata.size());
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));
    }
    catch (CryptoPP::BufferedTransformation::NoChannelSupport &e)
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    // cipher[ 0 ] |= 0x0F;
    // cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        // Break the cipher text out into it's
        //  components: Encrypted and MAC
        string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
        string tag = cipher.substr(cipher.length() - TAG_SIZE);

        // Sanity checks
        assert(cipher.size() == enc.size() + tag.size());
        assert(enc.size() == pdata.size());
        assert(TAG_SIZE == tag.size());

        // Not recovered - sent via clear channel
        radata = adata;

        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv, ivLength);
        d.SpecifyDataLengths(radata.size(), enc.size(), 0);

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df(d, NULL,
                                         //AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                         AuthenticatedDecryptionFilter::THROW_EXCEPTION);

        // The order of the following calls are important
        df.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        df.ChannelPut("", (const byte *)enc.data(), enc.size());
        df.ChannelPut("", (const byte *)tag.data(), tag.size());

        df.ChannelMessageEnd("AAD");
        df.ChannelMessageEnd("");

        // If the object does not throw, here's the only
        // opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert(true == b);

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel("");
        n = (size_t)df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0)
        {
            df.Get((byte *)retrieved.data(), n);
        }
        rpdata = retrieved;
        assert(rpdata == pdata);

        // Hmmm... No way to get the calculated MAC
        // tag out of the Decryptor/Verifier. At
        // least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == tag );

        // All is well - work with data
        wcout << "Decrypted and Verified data. Ready for use." << endl;
        wcout << endl;

        wcout << "adata length: " << adata.size() << endl;
        wcout << "pdata length: " << pdata.size() << endl;
        wcout << endl;

        //cout << "adata: " << adata << endl;
        //cout << "pdata: " << pdata << endl;
        //cout << endl;

        wcout << "cipher text (enc + tag): " << endl
              << " " << string_to_wstring(encoded) << endl;
        wcout << endl;

        wcout << "recovered adata length: " << radata.size() << endl;
        wcout << "recovered pdata length: " << rpdata.size() << endl;
        wcout << endl;

        //cout << "recovered adata: " << radata << endl;
        //cout << "recovered pdata: " << rpdata << endl;
        //cout << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e)
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
}
void option_AESGCM(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string adata(16, (char)0x00);
    string pdata(16, (char)0x00);

    const int TAG_SIZE = 16;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/

    try
    {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv, ivLength);
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef(e,
                                         new StringSink(cipher), false, TAG_SIZE); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut("", (const byte *)pdata.data(), pdata.size());
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));
    }
    catch (CryptoPP::BufferedTransformation::NoChannelSupport &e)
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e)
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    //  cipher[ 0 ] |= 0x0F;
    //  cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv, ivLength);

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
        string mac = cipher.substr(cipher.length() - TAG_SIZE);

        // Sanity checks
        assert(cipher.size() == enc.size() + mac.size());
        assert(enc.size() == pdata.size());
        assert(TAG_SIZE == mac.size());

        // Not recovered - sent via clear channel
        radata = adata;

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df(d, NULL,
                                         AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                             AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                         TAG_SIZE);

        // The order of the following calls are important
        df.ChannelPut("", (const byte *)mac.data(), mac.size());
        df.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        df.ChannelPut("", (const byte *)enc.data(), enc.size());

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd("AAD");
        df.ChannelMessageEnd("");

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert(true == b);

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel("");
        n = (size_t)df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0)
        {
            df.Get((byte *)retrieved.data(), n);
        }
        rpdata = retrieved;
        assert(rpdata == pdata);

        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        wcout << "Decrypted and Verified data. Ready for use." << endl;
        wcout << endl;

        wcout << "adata length: " << adata.size() << endl;
        wcout << "pdata length: " << pdata.size() << endl;
        wcout << endl;

        //cout << "adata: " << adata << endl;
        //cout << "pdata: " << pdata << endl;
        //cout << endl;

        wcout << "cipher text: " << endl
              << " " << string_to_wstring(encoded) << endl;
        wcout << endl;

        wcout << "recovered adata length: " << radata.size() << endl;
        wcout << "recovered pdata length: " << rpdata.size() << endl;
        wcout << endl;

        //cout << "recovered adata: " << radata << endl;
        //cout << "recovered pdata: " << rpdata << endl;
        //cout << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e)
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e)
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
}

void DisplayResult(double total)
{
    wcout << L"\nThời gian chạy 10.000 rounds: " << total << " ms" << endl;
    wcout << L"\nThời gian trung bình: " << total / 10000 << " ms" << endl;
}

void option_DESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    try
    {
        CBC_Mode<DES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }

    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    try
    {
        CBC_Mode<DES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_2TDESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    /*********************************\
	\*********************************/

    try
    {

        CBC_Mode<DES_EDE2>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    try
    {
        CBC_Mode<DES_EDE2>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_3TDESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    try
    {

        CBC_Mode<DES_EDE3>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded	-->OFB
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(              //BIEU DIEN THANH Base64Encoder
                     new StringSink(encoded)) // HexEncoder		//BIEU DIEN THANH Base64Encoder
    );                                        // StringSource

    try
    {
        CBC_Mode<DES_EDE3>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESECB_time(byte key[], wstring wplain, string plain, int keyLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "key: " << string_to_wstring(encoded) << endl;

    try
    {
        wcout << "plain text: " << wplain << endl;

        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, keyLength);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

    try
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, keyLength);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESCBC_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    try
    {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)) // StreamTransformationFilter
        );                                                                    // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    try
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESOFB_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    /*********************************\
	\*********************************/

    try
    {

        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // OFB mode must not use padding. Specifying
        //  a scheme will result in an exception
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    try
    {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESCFB_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    try
    {
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // CFB mode must not use padding. Specifying
        //  a scheme will result in an exception
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    try
    {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESCTR_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;

    // Pretty print key
    encoded.clear();
    StringSource(key, keyLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    // Pretty print iv
    encoded.clear();
    StringSource(iv, ivLength, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    try
    {

        CTR_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)) // StreamTransformationFilter
        );                                                                  // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    /*********************************\
	\*********************************/

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    /*********************************\
	\*********************************/

    try
    {
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)) // StreamTransformationFilter
        );                                                                       // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}
void option_AESXTS_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    string cipher, encoded, recovered;
    try
    {

        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter adds padding
        //  as requiredec. ECB and XTS Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plain, true,
                        new StreamTransformationFilter(enc,
                                                       new StringSink(cipher),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                                     // StringSource
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }

    // Pretty print cipher text
    StringSource ss(cipher, true,
                    new HexEncoder(
                        new StringSink(encoded)) // HexEncoder
    );                                           // StringSource

    try
    {
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, keyLength, iv);

        // The StreamTransformationFilter removes
        //  padding as requiredec.
        StringSource ss(cipher, true,
                        new StreamTransformationFilter(dec,
                                                       new StringSink(recovered),
                                                       StreamTransformationFilter::NO_PADDING) // StreamTransformationFilter
        );                                                                                     // StringSource
    }
    catch (const CryptoPP::Exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }
}
void option_AESCCM_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    //memset( iv, '8', ivLength );
    //string adata="Authenticated";
    //string pdata="Authenticated Encryption";
    //const int TAG_SIZE = 6;

    // Test Vector 003
    // byte key[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    //               0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    // byte iv[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    //              0x17, 0x18, 0x19, 0x1a, 0x1b};

    const byte aa[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};
    string adata = string((const char *)aa, sizeof(aa));

    const byte pa[] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                       0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                       0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    string pdata = string((const char *)pa, sizeof(pa));
    const int TAG_SIZE = 8;

    //CTX e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5
    //TAG 484392fbc1b09951

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/

    try
    {
        CCM<AES, TAG_SIZE>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv, ivLength);
        e.SpecifyDataLengths(adata.size(), pdata.size(), 0);

        AuthenticatedEncryptionFilter ef(e,
                                         new StringSink(cipher)); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data
        ef.ChannelPut("", (const byte *)pdata.data(), pdata.size());
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));
    }
    catch (CryptoPP::BufferedTransformation::NoChannelSupport &e)
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    // cipher[ 0 ] |= 0x0F;
    // cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        // Break the cipher text out into it's
        //  components: Encrypted and MAC
        string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
        string tag = cipher.substr(cipher.length() - TAG_SIZE);

        // Sanity checks
        assert(cipher.size() == enc.size() + tag.size());
        assert(enc.size() == pdata.size());
        assert(TAG_SIZE == tag.size());

        // Not recovered - sent via clear channel
        radata = adata;

        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv, ivLength);
        d.SpecifyDataLengths(radata.size(), enc.size(), 0);

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df(d, NULL,
                                         //AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                         AuthenticatedDecryptionFilter::THROW_EXCEPTION);

        // The order of the following calls are important
        df.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        df.ChannelPut("", (const byte *)enc.data(), enc.size());
        df.ChannelPut("", (const byte *)tag.data(), tag.size());

        df.ChannelMessageEnd("AAD");
        df.ChannelMessageEnd("");

        // If the object does not throw, here's the only
        // opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert(true == b);

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel("");
        n = (size_t)df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0)
        {
            df.Get((byte *)retrieved.data(), n);
        }
        rpdata = retrieved;
        assert(rpdata == pdata);

        // Hmmm... No way to get the calculated MAC
        // tag out of the Decryptor/Verifier. At
        // least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == tag );

        // All is well - work with data

        //cout << "adata: " << adata << endl;
        //cout << "pdata: " << pdata << endl;
        //cout << endl;

        //cout << "recovered adata: " << radata << endl;
        //cout << "recovered pdata: " << rpdata << endl;
        //cout << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e)
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
}
void option_AESGCM_time(byte key[], byte iv[], wstring wplain, string plain, int keyLength, int ivLength)
{
    //KEY 0000000000000000000000000000000000000000000000000000000000000000
    //IV  000000000000000000000000
    //HDR 00000000000000000000000000000000
    //PTX 00000000000000000000000000000000
    //CTX cea7403d4d606b6e074ec5d3baf39d18
    //TAG ae9b1771dba9cf62b39be017940330b4

    // Test Vector 003
    // byte key[32];
    // memset(key, 0, keyLength);
    // byte iv[12];
    // memset(iv, 0, ivLength);

    string adata(16, (char)0x00);
    string pdata(16, (char)0x00);

    const int TAG_SIZE = 16;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/

    try
    {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, keyLength, iv, ivLength);
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef(e,
                                         new StringSink(cipher), false, TAG_SIZE); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut("", (const byte *)pdata.data(), pdata.size());
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));
    }
    catch (CryptoPP::BufferedTransformation::NoChannelSupport &e)
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e)
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    //  cipher[ 0 ] |= 0x0F;
    //  cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, keyLength, iv, ivLength);

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
        string mac = cipher.substr(cipher.length() - TAG_SIZE);

        // Sanity checks
        assert(cipher.size() == enc.size() + mac.size());
        assert(enc.size() == pdata.size());
        assert(TAG_SIZE == mac.size());

        // Not recovered - sent via clear channel
        radata = adata;

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df(d, NULL,
                                         AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                             AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                         TAG_SIZE);

        // The order of the following calls are important
        df.ChannelPut("", (const byte *)mac.data(), mac.size());
        df.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        df.ChannelPut("", (const byte *)enc.data(), enc.size());

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd("AAD");
        df.ChannelMessageEnd("");

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert(true == b);

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel("");
        n = (size_t)df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0)
        {
            df.Get((byte *)retrieved.data(), n);
        }
        rpdata = retrieved;
        assert(rpdata == pdata);

        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        // wcout << "Decrypted and Verified data. Ready for use." << endl;
        // wcout << endl;

        // wcout << "adata length: " << adata.size() << endl;
        // wcout << "pdata length: " << pdata.size() << endl;
        // wcout << endl;

        //cout << "adata: " << adata << endl;
        //cout << "pdata: " << pdata << endl;
        //cout << endl;

        // wcout << "cipher text: " << endl
        //       << " " << string_to_wstring(encoded) << endl;
        // wcout << endl;

        // wcout << "recovered adata length: " << radata.size() << endl;
        // wcout << "recovered pdata length: " << rpdata.size() << endl;
        // wcout << endl;

        //cout << "recovered adata: " << radata << endl;
        //cout << "recovered pdata: " << rpdata << endl;
        //cout << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e)
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e)
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
}
