#pragma once
#include <windows.h>
#include <locale> 
#include <iostream> 
#include <string>    

using namespace std;
#define MAX_LENGTH	0x1000

class HuyInput
{
	public:
		static wstring ReadString();
		static wstring ReadString(const wstring title);
		static wstring ReadString(const string title);

		static void WriteString();
		static void WriteString(const wstring title);
		static void WriteString(const string title);

		static int Size(const wstring title);
		static int Size(const string title);

		static int ReadInt();
		static int ReadInt(const wstring title);
		static int ReadInt(const string title);

		static double ReadDouble();
		static double ReadDouble(const wstring title);
		static double ReadDouble(const string title);

		static float ReadFloat();
		static float ReadFloat(const wstring title);
		static float ReadFloat(const string title);

		static wstring ToUnicode(int n);
		static wstring ToUnicode(double d);
		static wstring ToUnicode(float f);
};