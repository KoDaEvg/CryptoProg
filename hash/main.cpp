#include <iostream>
#include <fstream>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
using namespace std;
int main ()
{
    ifstream fila("HashingText.txt");
    fila.seekg(0,ios::end);
    int fsize = fila.tellg();
    fila.seekg(0,ios::beg);
    char* buf = new char[fsize];
    fila.read(buf,fsize);
    string file = string(buf);
    fila.close();
    cout << "Text from file is: " << buf << endl;
    using namespace CryptoPP;
    SHA1 hash;
    string digest;
    StringSource(file, true,
               new HashFilter(hash,
                              new HexEncoder(
                                  new StringSink(digest))));
    cout << "Hashedtext is: " << digest << endl;
    return 0;
}
