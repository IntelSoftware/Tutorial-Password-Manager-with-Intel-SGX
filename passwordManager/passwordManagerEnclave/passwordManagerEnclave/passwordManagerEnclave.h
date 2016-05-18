#include <string>
#include <map>

using namespace std;

#define MAX_BUF_LEN 100
typedef struct{
	string password;
	string url;
	string account;
	//int token; //user is authorized to see/edit data
	//add more if necessary
} Metadata;


std::map<string,Metadata> keypass; //matches username with account info
std::map<string,Metadata>::iterator it;//_metadata;
int size = 0;

int addUser(char*, char*, size_t); //ECALL
bool authenticate(string,string);
bool decryptPassword(string*);
bool encryptPassword(string*);
int findUser(char*,size_t);

int getAccount(char*, size_t); //ECALL
int getPassword(char*, size_t); //ECALL, debug
int getUrl(char*, size_t); //ECALL
int removeUser(char*, size_t); //ECAL
//NOTE: since the code is written under the assumption that there will be a GUI 
// wrapper, setter functions assume user is authenticated
int setAccount(char*, char*, size_t); //ECALL
int setPassword(char*, char*, size_t); //ECALL
int setUrl(char*, char*, size_t); //ECALL



