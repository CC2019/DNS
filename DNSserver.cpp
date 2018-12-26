// Udp_server.cpp : �������̨Ӧ�ó������ڵ㡣
//
#include "stdafx.h"
#include "stdio.h"
#include<mutex>
#include <iostream>  
#include <fstream>  
#include <string>  
#include <Vector>
#include<time.h>
#include<ctime>
#include <sstream>  
#include <iomanip>
#include <WINSOCK2.H>  
#include<thread>
using namespace std;
#pragma warning(disable : 4996)
#pragma comment(lib,"WS2_32.lib")  
#define BUF_SIZE    256

int num;

#pragma pack(push, 1)
mutex print_lock;
mutex num_plus;
mutex num_d;
struct DNSHeader
{
	/* 1. �Ự��ʶ��2�ֽڣ�*/
	unsigned short usTransID;        // Transaction ID

									 /* 2. ��־����2�ֽڣ�*/
	unsigned char RD : 1;            // ��ʾ�����ݹ飬1bit
	unsigned char TC : 1;            // ��ʾ�ɽضϵģ�1bit
	unsigned char AA : 1;            // ��ʾ��Ȩ�ش�1bit
	unsigned char opcode : 4;        // 0��ʾ��׼��ѯ��1��ʾ�����ѯ��2��ʾ������״̬����4bit
	unsigned char QR : 1;            // ��ѯ/��Ӧ��־λ��0Ϊ��ѯ��1Ϊ��Ӧ��1bit

	unsigned char rcode : 4;         // ��ʾ�����룬4bit
	unsigned char zero : 3;          // ����Ϊ0��3bit
	unsigned char RA : 1;            // ��ʾ���õݹ飬1bit

									 /* 3. �����ֶΣ���8�ֽڣ� */
	unsigned short Questions;        // ������
	unsigned short AnswerRRs;        // �ش���Դ��¼��
	unsigned short AuthorityRRs;     // ��Ȩ��Դ��¼��
	unsigned short AdditionalRRs;    // ������Դ��¼��
};
#pragma pack(pop)
struct TH {
	char buffer[BUF_SIZE];
	int n;
	string name;
	unsigned short ID;
	SOCKADDR_IN ADDRClient;
	SOCKET SocketSrv;
	int type;
	int number;
};

void server_decode(char* buffer, int lenth, string &Name, unsigned short &TransID, SOCKADDR_IN addrClient, SOCKET socketSrv,int type,int number);

DWORD WINAPI myfun1(LPVOID P)
{
	TH* pN = (TH*)P;
	server_decode(pN->buffer, pN->n, pN->name, pN->ID, pN->ADDRClient, pN->SocketSrv,pN->type,pN->number);
	num_d.lock();
	num--;
	num_d.unlock();
	return 0;
}

//DWORD WINAPI myfun2(LPVOID lpParameter){}




string all[1000];
string ipadd[1000];
string dm[1000];

vector<string> split(string &str, string pattern)
{
	int pos;
	vector<string> result;
	if (str == "")
	{
		return result;
	}
	str += pattern;
	int size = str.size();
	for (int i = 0; i < size; i++)
	{
		pos = str.find(pattern, i);
		if (pos < size)
		{
			string tmp = str.substr(i, pos - i);
			result.push_back(tmp);
			i = pos + pattern.size() - 1;
		}
	}
	str = str.substr(0, size - pattern.length());
	return result;
}

bool SendDnsPack(IN unsigned short usID,
	IN SOCKET *pSocket,
	IN const char *szDnsServer,
	IN const char *szDomainName)
{
	bool bRet = false;

	if (*pSocket == INVALID_SOCKET
		|| szDomainName == NULL
		|| szDnsServer == NULL
		|| strlen(szDomainName) == 0
		|| strlen(szDnsServer) == 0)
	{
		return bRet;
	}

	unsigned int uiDnLen = strlen(szDomainName);

	// �ж������Ϸ��ԣ�����������ĸ�����ǵ�ţ�������
	// ����������������ĵ�� 
	if ('.' == szDomainName[0] || ('.' == szDomainName[uiDnLen - 1]
		&& '.' == szDomainName[uiDnLen - 2])
		)
	{
		return bRet;
	}

	/* 1. ������ת��Ϊ���ϲ�ѯ���ĵĸ�ʽ */
	// ��ѯ���ĵĸ�ʽ�����������ģ�
	//      6 j o c e n t 2 m e 0
	unsigned int uiQueryNameLen = 0;
	BYTE *pbQueryDomainName = (BYTE *)malloc(uiDnLen + 1 + 1);
	if (pbQueryDomainName == NULL)
	{
		return bRet;
	}
	// ת����Ĳ�ѯ�ֶγ���Ϊ�������� +2
	memset(pbQueryDomainName, 0, uiDnLen + 1 + 1);

	// �����ѭ���������£�
	// �������Ϊ  jocent.me ����ת������ 6 j o c e n t  ������һ����û�и���
	// �������Ϊ  jocent.me.����ת������ 6 j o c e n t 2 m e
	unsigned int uiPos = 0;
	unsigned int i = 0;
	for (i = 0; i < uiDnLen; ++i)
	{
		if (szDomainName[i] == '.')
		{
			pbQueryDomainName[uiPos] = i - uiPos;
			if (pbQueryDomainName[uiPos] > 0)
			{
				memcpy(pbQueryDomainName + uiPos + 1, szDomainName + uiPos, i - uiPos);
			}
			uiPos = i + 1;
		}
	}

	// �������������ǵ�ţ���ô�����ѭ��ֻת����һ����
	// ����Ĵ������ת��ʣ��Ĳ��֣� ���� 2 m e
	if (szDomainName[i - 1] != '.')
	{
		pbQueryDomainName[uiPos] = i - uiPos;
		memcpy(pbQueryDomainName + uiPos + 1, szDomainName + uiPos, i - uiPos);
		uiQueryNameLen = uiDnLen + 1 + 1;
	}
	else
	{
		uiQueryNameLen = uiDnLen + 1;
	}
	// �������  ͷ�� + name + type + class
	DNSHeader *PDNSPackage = (DNSHeader*)malloc(sizeof(DNSHeader) + uiQueryNameLen + 4);
	if (PDNSPackage == NULL)
	{
		cout << "wrong 146" << endl;
		//	goto exit;
	}
	memset(PDNSPackage, 0, sizeof(DNSHeader) + uiQueryNameLen + 4);

	// ���ͷ������
	PDNSPackage->usTransID = htons(usID);  // ID
	PDNSPackage->RD = 0x1;   // ��ʾ�����ݹ�
	PDNSPackage->Questions = htons(0x1);  // ���ĵ�һ����ʾ��������htons����ת��

										  // �����������  name + type + class
	BYTE* PText = (BYTE*)PDNSPackage + sizeof(DNSHeader);
	memcpy(PText, pbQueryDomainName, uiQueryNameLen);

	unsigned short *usQueryType = (unsigned short *)(PText + uiQueryNameLen);
	*usQueryType = htons(0x1);        // TYPE: A

	++usQueryType;
	*usQueryType = htons(0x1);        // CLASS: IN    

									  // ��Ҫ���͵���DNS�������ĵ�ַ
	sockaddr_in dnsServAddr = {};
	dnsServAddr.sin_family = AF_INET;
	dnsServAddr.sin_port = ::htons(53);  // DNS����˵Ķ˿ں�Ϊ53
	dnsServAddr.sin_addr.S_un.S_addr = ::inet_addr(szDnsServer);


	//	server_decode((char*)PDNSPackage, 255);

	// ����ѯ���ķ��ͳ�ȥ
	int nRet = ::sendto(*pSocket,
		(char*)PDNSPackage,
		sizeof(DNSHeader) + uiQueryNameLen + 4,
		0,
		(sockaddr*)&dnsServAddr,
		sizeof(dnsServAddr));
	if (SOCKET_ERROR == nRet)
	{
		printf("DNSPackage Send Fail! \n");
		//goto exit;
	}

	// printf("DNSPackage Send Success! \n");
	bRet = true;

	// ͳһ����Դ����       
	exit:
	if (PDNSPackage)
	{
	free(PDNSPackage);
	PDNSPackage = NULL;
	}

	if (pbQueryDomainName)
	{
	free(pbQueryDomainName);
	pbQueryDomainName = NULL;
	}

	return bRet;
}

unsigned int RecvDnsPack(IN unsigned short usId,
	IN SOCKET *pSocket)
{
	if (*pSocket == INVALID_SOCKET)
	{
		return 0;
	}

	char szBuffer[256] = {};        // ������յ�������
	sockaddr_in servAddr = {};
	int iFromLen = sizeof(sockaddr_in);

	int iRet = ::recvfrom(*pSocket,
		szBuffer,
		256,
		0,
		(sockaddr*)&servAddr,
		&iFromLen);
	if (SOCKET_ERROR == iRet || 0 == iRet)
	{
		cout << "recv fail \n";
		return 0;
	}

	/* �����յ������� */
	DNSHeader *PDNSPackageRecv = (DNSHeader *)szBuffer;
	unsigned int uiTotal = iRet;        // ���ֽ���
	unsigned int uiSurplus = iRet;  // ���ܵ����ܵ��ֽ���

									// ȷ���յ���szBuffer�ĳ��ȴ���sizeof(DNSHeader)
	if (uiTotal <= sizeof(DNSHeader))
	{
		cout << "���յ������ݳ��Ȳ��Ϸ�\n";
		return 0;
	}

	// ȷ��PDNSPackageRecv�е�ID�Ƿ��뷢�ͱ����е���һ�µ�
	unsigned short AAA = usId;
	AAA = htons(usId);
	if (htons(usId) != PDNSPackageRecv->usTransID)
	{
		cout << "���յ��ı���ID���ѯ���Ĳ����\n";
		return 0;
	}

	// ȷ��PDNSPackageRecv�е�FlagsȷʵΪDNS����Ӧ����
	if (0x01 != PDNSPackageRecv->QR)
	{
		cout << "���յ��ı��Ĳ�����Ӧ����\n";
		return 0;
	}

	// ��ȡQueries�е�type��class�ֶ�
	unsigned char *pChQueries = (unsigned char *)PDNSPackageRecv + sizeof(DNSHeader);
	uiSurplus -= sizeof(DNSHeader);

	for (; *pChQueries && uiSurplus > 0; ++pChQueries, --uiSurplus) { ; } // ����Queries�е�name�ֶ�

	++pChQueries;
	--uiSurplus;

	if (uiSurplus < 4)
	{
		cout << "���յ������ݳ��Ȳ��Ϸ�\n";
		return 0;
	}

	unsigned short usQueryType = ntohs(*((unsigned short*)pChQueries));
	pChQueries += 2;
	uiSurplus -= 2;

	unsigned short usQueryClass = ntohs(*((unsigned short*)pChQueries));
	pChQueries += 2;
	uiSurplus -= 2;

	// ����Answers�ֶ�
	unsigned char *pChAnswers = pChQueries;
	while (0 < uiSurplus && uiSurplus <= uiTotal)
	{
		// ����name�ֶΣ����ã�
		unsigned char aaa = *pChAnswers;
		if (*pChAnswers == 0xC0)  // ��ŵ���ָ��
		{
			if (uiSurplus < 2)
			{
				cout << "���յ������ݳ��Ȳ��Ϸ�\n";
				return 0;
			}
			pChAnswers += 2;       // ����ָ���ֶ�
			uiSurplus -= 2;
		}
		else        // ��ŵ�������
		{
			// ������������Ϊ�Ѿ�У����ID�������Ͳ�����
			for (; *pChAnswers && uiSurplus > 0; ++pChAnswers, --uiSurplus) { ; }
			pChAnswers++;
			uiSurplus--;
		}

		if (uiSurplus < 4)
		{
			cout << "���յ������ݳ��Ȳ��Ϸ�\n";
			return 0;
		}

		unsigned short usAnswerType = ntohs(*((unsigned short*)pChAnswers));
		pChAnswers += 2;
		uiSurplus -= 2;

		unsigned short usAnswerClass = ntohs(*((unsigned short*)pChAnswers));
		pChAnswers += 2;
		uiSurplus -= 2;

		if ((usAnswerType != usQueryType || usAnswerClass != usQueryClass) && usAnswerType != 0x05)
		{
		//	cout << "���յ�������Type��Class�뷢�ͱ��Ĳ�һ��\n" << endl;
			return 0;
		}

		pChAnswers += 4;    // ����Time to live�ֶΣ�����DNS Client��˵������ֶ�����
		uiSurplus -= 4;

		if (htons(0x04) != *(unsigned short*)pChAnswers)
		{
			uiSurplus -= 2;     // ����data length�ֶ�
			unsigned short leap = ntohs(*(unsigned short*)pChAnswers);
			uiSurplus -= ntohs(*(unsigned short*)pChAnswers); // ����������length

			pChAnswers += 2;
			pChAnswers += leap;
		}
		else
		{
			if (uiSurplus < 6)
			{
				cout << "���յ������ݳ��Ȳ��Ϸ�\n";
				return 0;
			}
			uiSurplus -= 6;
			// TypeΪA, ClassΪIN
			if (usAnswerType == 1 && usAnswerClass == 1)
			{
				pChAnswers += 2;
				unsigned int uiIP = *(unsigned int*)pChAnswers;
				return uiIP;
				in_addr in = {};
				in.S_un.S_addr = uiIP;
				//printf("IP: %s\n", inet_ntoa(in));

				pChAnswers += 4;
			}
			else
			{
				pChAnswers += 6;
			}
		}
	}
	return 0;
}

unsigned int toRealServer(char* name)
{
	WSADATA wsaData = {};
	if (0 != ::WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		printf("WSAStartup fail \n");
		return -1;
	}

	SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (INVALID_SOCKET == socket)
	{
		printf("socket fail \n");
		return -1;
	}

	int nNetTimeout = 2000;

	// ���÷���ʱ��
	::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&nNetTimeout, sizeof(int));
	// ���ý���ʱ��
	::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&nNetTimeout, sizeof(int));

	// �������һ��ID
	srand((unsigned int)time(NULL));
	unsigned short usId = (unsigned short)rand();

	//	while (true)
	//	{
	// �Զ�����Ҫ��ѯ������
	//	char szDomainName[256] = {};
	//	szDomainName = name;
	//	cin >> szDomainName;

	// ����DNS���ģ���Ϊ���ԣ�����ͼ�ָ��127.0.0.1��Ϊ��ѯ������
	char name1[256];
	for (int i = 0; i < 256; i++)
		name1[i] = *(name++);
	//cout << name1;
	if (!SendDnsPack(usId, &socket, "8.8.8.8", name1))//192.168.1.108
	{
		return -1;
	}

	// ������Ӧ���ģ�����ʾ��õ�IP��ַ
	unsigned int AAA = RecvDnsPack(usId, &socket);
	//	}

	closesocket(socket);

	WSACleanup();
	return AAA;
}//111.13.100.91

void server_decode(char* buffer, int lenth, string &Name, unsigned short &TransID, SOCKADDR_IN addrClient, SOCKET socketSrv,int type,int number)
{
	string domainName = "";
	DNSHeader* QDHeader = (DNSHeader*)buffer;
	unsigned short AA = htons(QDHeader->usTransID);
	if (lenth < sizeof(DNSHeader))
	{
		cout << "illegal packet" << endl;
		return;
	}
	if (0x0 != QDHeader->QR)
	{
		cout << "not query packet" << endl;
		return;
	}
	TransID = QDHeader->usTransID;
	unsigned char* Query = (unsigned char*)QDHeader + sizeof(DNSHeader);
	int name_lenth = (int)*Query;
	int iii = 0;
	char name[256];
	for (int i = 0; i < 256; i++)
		name[i] = '\0';
	while (name_lenth != 0)
	{
		int lenth_count = name_lenth;
		char* show_name = (char*)Query;
		for (; lenth_count > 0; lenth_count--)
		{
			show_name = show_name + 1;
			name[iii++] = *show_name;
			domainName = domainName + *show_name;
		}
		Query = Query + 1 + name_lenth;
		name_lenth = (int)*Query;
		if (name_lenth != 0)
		{
			name[iii++] = '.';
			domainName = domainName + ".";
		}
	}
	Query = Query + 1;
	BYTE* DNSAnswer = (BYTE*)malloc(lenth + 16);
	memset(DNSAnswer, 0, sizeof(DNSAnswer) + 16);
	memcpy(DNSAnswer, buffer, lenth);              //DNSHead����װ����
	DNSHeader* ADHeader = (DNSHeader*)DNSAnswer;
	ADHeader->QR = 0x01;
	//ADHeader->usTransID = htons(ADHeader->usTransID);
	BYTE* Record = DNSAnswer + lenth;

	int* NameRe = (int*)Record;
	*NameRe = htons(0xC00C);
	unsigned short* Query_type = (unsigned short*)Query;
	Query = Query + 2;
	memcpy(Record + 2, Query_type, 2);

	unsigned short* Query_class = (unsigned short*)Query;
	memcpy(Record + 4, Query_class, 2);
	unsigned char* IP_address = Record + 12;
	unsigned char* dataLenth_1 = Record + 10;
	unsigned int* timeToLive;
	timeToLive = (unsigned int*)(Record + 6);
	*timeToLive = 0;
	unsigned short* timeToLive1 = (unsigned short*)timeToLive;
	timeToLive1 += 1;
	*timeToLive1 = 0xF401;
	unsigned short* dataLenth = (unsigned short*)dataLenth_1;
	*(dataLenth) = htons(0x0004);
	int num1 = 255, num2 = 255, num3 = 255, num4 = 255;
	int flag = 0;
	unsigned short uiIP[4];
	unsigned char* temp = IP_address;
	for (int j = 0; j < 1000; j++)
	{
		//cout << dm[j] << endl;
		if (dm[j] == domainName)
		{
			vector<string>ip_a = split(ipadd[j], ".");
			num1 = std::atoi(ip_a[0].c_str());
			num2 = std::atoi(ip_a[1].c_str());
			num3 = std::atoi(ip_a[2].c_str());
			num4 = std::atoi(ip_a[3].c_str());
			*(IP_address++) = num1;
			*(IP_address++) = num2;
			*(IP_address++) = num3;
			*(IP_address++) = num4;
			flag = 1;
		}

	}
	if (flag == 0)
	{
		unsigned int AAA = toRealServer(name);
		unsigned char* BBB = (unsigned char*)(&AAA);
		*(IP_address++) = *BBB;
		*(IP_address++) = *(BBB + 1);
		*(IP_address++) = *(BBB + 2);
		*(IP_address++) = *(BBB + 3);
	}
	for (int i = 0; i < 4; i++)
	{
		uiIP[i] = 0;
		uiIP[i] = (int)(*temp++);
	}
	const char* Resend = (const char*)DNSAnswer;
	DNSHeader* fina = (DNSHeader*)Resend;
	fina->AnswerRRs = htons(0x1);
	time_t now_time;
	now_time = time(NULL);
	//printf("IP: %s\n", inet_ntoa(in));
	if (type == 1)
	{
		print_lock.lock();
		cout << "No." << number << "\t" << now_time << "\t" << "IP: " << uiIP[0] << "." << uiIP[1] << "." << uiIP[2] << "." << uiIP[3] << "\t" << name << endl;
		print_lock.unlock();
	}
	sendto(socketSrv, Resend, lenth + 16, 0, (SOCKADDR*)&addrClient, sizeof(SOCKADDR));
}


int main(void)
{
	int number = 0;
	string temp;
	int i = 0;
	ifstream f("dnsrelay.txt");//txt��cppͬһĿ¼��
	if (!f.is_open())
	{
		cout << "δ�ɹ����ļ�" << endl;
	}
	while (getline(f, temp))
	{
		all[i] = temp;
		if (all[i] != "")
		{
			vector<string> depart = split(all[i], " ");
			ipadd[i] = depart[0];
			dm[i] = depart[1];
			i++;
		}
		//cout << dm[i] << endl;
	}
	WSADATA wsd;
	SOCKET  s;
	int     nRet;
	int		type;


	cout << "�����빤��ģʽ ��0��1����";
	cin >> type;
	// ��ʼ���׽��ֶ�̬��  
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		cout << "WSAStartup failed !/n";
		return 1;
	}

	// �����׽���  
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == INVALID_SOCKET)
	{
		cout << "socket() failed ,Error Code:" << WSAGetLastError() << endl;
		WSACleanup();
		return 1;
	}

	SOCKET      socketSrv = socket(AF_INET, SOCK_DGRAM, 0);
	SOCKADDR_IN addrSrv;
	SOCKADDR_IN addrClient;
	char        buf[BUF_SIZE];
	int         len = sizeof(SOCKADDR);

	// ���÷�������ַ  
	ZeroMemory(buf, BUF_SIZE);
	addrSrv.sin_addr.S_un.S_addr = ::inet_addr("172.20.10.5");
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(53);

	// ���׽���  
	nRet = ::bind(socketSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	if (SOCKET_ERROR == nRet)
	{
		cout << "bind failed !/n";
		closesocket(s);
		WSACleanup();
		return -1;
	}
	while (true)
	{
		int k = 1;
		ZeroMemory(buf, BUF_SIZE);
		// �ӿͻ��˽�������  
		nRet = recvfrom(socketSrv, buf, BUF_SIZE, 0, (SOCKADDR*)&addrClient, &len);
		if (SOCKET_ERROR == nRet)
		{
			cout << "recvfrom failed !\n";
			k = 0;
		}
	if (num < 10 && k == 1)
		{
			num_plus.lock();
			num++;
			num_plus.unlock();
			//�����ճɹ�������һ���߳�
			HANDLE h1;//�����������  
			string domainName;
			unsigned short transID = 0;
			TH t1;
			for (int i = 0; i < BUF_SIZE; i++)
				t1.buffer[i] = buf[i];
			t1.n = nRet;
			t1.name = domainName;
			t1.ID = transID;
			t1.ADDRClient = addrClient;
			t1.SocketSrv = socketSrv;
			t1.type = type;
			t1.number = number++;
			h1 = CreateThread(NULL, 0, myfun1, &t1, 0, NULL);//�����߳�1  
			CloseHandle(h1);
		}
	}
	closesocket(s);
	WSACleanup();
	system("pause");
	return 0;
}