#include "HuyInput.h" 

wstring HuyInput::ReadString() {
	wchar_t buffer[MAX_LENGTH];
	size_t numRead = 0;
	_cgetws_s(buffer, &numRead);
	return buffer; 
}
wstring HuyInput::ReadString(const wstring title) {
	WriteString(title);
	return ReadString();
}
wstring HuyInput::ReadString(const string title) {
	WriteString(title);
	return ReadString();
}

void HuyInput::WriteString() {
	cout << endl;
}
void HuyInput::WriteString(const wstring title) {
	const wchar_t* wcs = title.c_str();
	_cputws(wcs);
}
void HuyInput::WriteString(const string title) {
	cout << title;
}

int HuyInput::Size(const wstring str) {
	return str.size();
}
int HuyInput::Size(const string str) {
	return str.length();
}

int HuyInput::ReadInt() {
	int so;
	cin >> so;
	return so;
}
int HuyInput::ReadInt(const wstring title) {
	WriteString(title);
	return ReadInt();
}
int HuyInput::ReadInt(const string title) {
	WriteString(title);
	return ReadInt();
}

double HuyInput::ReadDouble() {
	double so;
	cin >> so;
	return so;
}
double HuyInput::ReadDouble(const wstring title) {
	WriteString(title);
	return ReadDouble();
}
double HuyInput::ReadDouble(const string title) {
	WriteString(title);
	return ReadDouble();
}

float HuyInput::ReadFloat() {
	float so;
	cin >> so;
	return so;
}
float HuyInput::ReadFloat(const wstring title) {
	WriteString(title);
	return ReadFloat();
}
float HuyInput::ReadFloat(const string title) {
	WriteString(title);
	return ReadFloat();
}

wstring HuyInput::ToUnicode(int n) {
	return to_wstring(n);
}
wstring HuyInput::ToUnicode(double d) {
	return to_wstring(d);
}
wstring HuyInput::ToUnicode(float f) {
	return to_wstring(f);
}