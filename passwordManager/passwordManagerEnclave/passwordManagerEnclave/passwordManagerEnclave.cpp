#include "passwordManagerEnclave_t.h"
#include "passwordManagerEnclave.h"
#include "sgx_trts.h"




int addUser(char *username, char *password, size_t len)
{
	if(keypass.find(string(username)) != keypass.end() || username == NULL 
		|| password == NULL)
		//username is invalid, or already exists
		return -1;
	
	Metadata data;
	data.password = password;
	//if(!encryptPassword(&data.password))
	//	return -1;
	//keypass.insert(std::make_pair(string(username),string(password)));
	keypass[username] = data;
	size++;
	return 0;
}

int authenticate(char *username, char *password, size_t len)
{
	string passwd = string(password);
	if(!encryptPassword(&passwd)) return -1;
	it = keypass.find(string(username));
	if(it == keypass.end() || passwd.compare(it->second.password) != 0) 
		return -1;

	return 0;
}




bool decryptPassword(string *password)
{
	if(password == NULL) return false;
	//do crypto stuff
	return true;
}


bool encryptPassword(string *password)
{
	if(password == NULL) return false;
	//do crypto stuff; i believe jpmechalas is handling this
	return true;
}



int findUser(char *username, size_t len)
{
	it = keypass.find(string(username));
	if(it == keypass.end())
		//username does not exist
		return -1;
	return 0;
}

/* Skeleton code, if another parameter is added to the metadata
int getXXX(char *username, size_t len)
{
	it = keypass.find(string(username));
	if(it == keypass.end())
		//username does not exist
		return -1;

	Metadata data = it->second;
	memcpy(username,(void*)&data.XXX,data.XXX.size()+1);
	return 0;
}
*/

int getAccount(char *username, size_t len)
{
	it = keypass.find(string(username));
	if(it == keypass.end())
		//username does not exist
		return -1;

	Metadata data = it->second;
	memcpy(username,(void*)&data.account,data.account.size()+1);
	return 0;
}


/*
This is for debug purposes;
Takes username as input then replaces the string with password, if any)
*/
int getPassword(char *username, size_t len)
{
	it = keypass.find(string(username));
	if(it == keypass.end())
		//username does not exist
		return -1;

	Metadata data = it->second;

	//string password(MAX_BUF_LEN,'\0');
	//memcpy((void*)&password,it->second.c_str(),strlen(it->second.c_str())+1);
	//if(!decryptPassword(&data.password))
	//	return -1;
	memcpy(username,(void*)&data.password,data.password.size()+1);
	return 0;
}

int getSize()
{
	return size;
}

int getUrl(char *username, size_t len)
{
	it = keypass.find(string(username));
	if(it == keypass.end())
		//username does not exist
		return -1;

	Metadata data = it->second;
	memcpy(username,(void*)&data.url,data.url.size()+1);
	return 0;
}




int removeUser(char *username, size_t len)
{
	//if(!authenticate(username,password))
	//	return -1;
	if(keypass.erase(username) != 1)
		return -1;
	size--;
	return 0;
}



/*
int setXXX(char *username, char *newVal, size_t len)
{
	it = keypass.find(string(username));
	Metadata data = it->second;
	data.XXX = newVal;
	it->second = data;
	
	return 0;
}
*/

int setAccount(char *username, char *newVal, size_t len)
{
	it = keypass.find(string(username));
	Metadata data = it->second;
	data.account = newVal;
	it->second = data;
	
	return 0;
}


int setPassword(char *username, char *newVal, size_t len)
{
	/*
	if(it == keypass.end())
		//username does not exist
		return -1;
	if(!authenticate(username,oldPasswd))
		return -1;
	*/

	it = keypass.find(string(username));
	Metadata data = it->second;
	data.password = newVal;
	it->second = data;
	//memcpy((void*)(it->second.c_str()),password,strlen(password)+1);
	
	return 0;
}

int setUrl(char *username, char *newVal, size_t len)
{
	it = keypass.find(string(username));
	Metadata data = it->second;
	data.url = newVal;
	it->second = data;
	
	return 0;
}