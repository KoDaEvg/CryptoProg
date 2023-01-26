#include <iostream>
#include <vector>
#include <string.h>
#include <fstream>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/files.h>
#include <getopt.h>

using namespace std;

int main (int argc, char* argv[])
{
    string rjournal = "Rezult.txt";
    const char * sourse = "Text.txt";
    const char * journal = "Rezult.txt";
    const char * iv_file = "iv.hex";
    string password = "";
    string salt = "Когда нибудь я допишу курсовую работу!";
    int rejime = 0;
    static struct option long_options[] = {
        {"rejime", 1, 0, 'm'},
        {"sourse", 1, NULL, 's'},
        {"journal", 1, NULL, 'j'},
        {"password", 1, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };
    int opt;
    while((opt = getopt_long(argc, argv, ":m:s:j:p:", long_options, NULL))!= -1) {
        if ((char)opt == 'm') {
            if (string(optarg) == "encrypt" or string(optarg) == "e") {
                rejime = 2;
            } else if (string(optarg) == "decrypt" or string(optarg) == "d") {
                rejime = 1;
            } else {
                cout << "Error:Unknown option\n";
                return 0;
            }
        } else if ((char)opt == 's') {
            sourse = optarg;
        } else if ((char)opt == 'j') {
            journal = optarg;
        }  else if ((char)opt == 'p') {
            password = string(optarg);
        } else if ((char)opt == ':') {
            cout << "Error:Unknown arguement\n";
            return 0;
        } else {
            cout << "Error:Unknown parameter\n";
            return 0;
        }
    }
    if (password == "") {
        cout << "Error:Unknown password\n";
        return 0;
    }
    using namespace CryptoPP;
    
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        PKCS12_PBKDF <SHA384> pbksha;
        pbksha.DeriveKey(key.data(), key.size(), 0, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), 1500, 0.0f);
    if (rejime == 1) {
        try {
            byte iv[AES::BLOCKSIZE];
            FileSource(iv_file, true,
                       new HexDecoder(
                           new ArraySink(iv, sizeof iv)));
            CBC_Mode<AES>::Decryption decr;
            decr.SetKeyWithIV(key, sizeof key, iv);
            FileSource (sourse, true,
                            new HexDecoder(
                                  new StreamTransformationFilter(decr,
                                          new FileSink(journal))));
        } catch(const Exception& e) {
            cerr << e.what() << endl;
            exit(1);
        }
    } else if (rejime == 2) {
        AutoSeededRandomPool prng;
        byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));
        StringSource(iv, sizeof(iv), true,
                               new HexEncoder(
                                   new FileSink(iv_file)));
        CBC_Mode<AES>::Encryption encr;
        encr.SetKeyWithIV( key, sizeof key, iv );
        FileSource (sourse, true,
                              new StreamTransformationFilter(encr,
                                    new HexEncoder(
                                        new FileSink(journal))));
    } else {
        cout << "Error:Unknown rejime\n";
    }
}