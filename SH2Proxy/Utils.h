#include <stdio.h>
#include <map>
#include <unordered_map>
#include <vector>
#include <string>
#include <list>
#include <atomic>
#include <locale>
#include <codecvt>
#include <thread>

#define STATIC

#if defined(_WIN32)
class fwPlatformString : public std::wstring
{
private:
	inline std::wstring ConvertString(const char* narrowString)
	{
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> converter;
		return converter.from_bytes(narrowString);
	}

public:
	fwPlatformString()
		: std::wstring()
	{
	}

	fwPlatformString(const std::wstring& arg)
		: std::wstring(arg)
	{
	}

	fwPlatformString(const wchar_t* arg)
		: std::wstring(arg)
	{
	}

	inline fwPlatformString(const std::string& narrowString)
		: std::wstring(ConvertString(narrowString.c_str()))
	{

	}

	inline fwPlatformString(const char* narrowString)
		: std::wstring(ConvertString(narrowString))
	{

	}
};
typedef wchar_t pchar_t;

#define _pfopen _wfopen
#define _P(x) L##x
#else
class fwPlatformString : public std::string
{
private:
	inline std::string ConvertString(const wchar_t* wideString)
	{
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> converter;
		return converter.to_bytes(wideString);
	}

public:
	fwPlatformString()
		: std::string()
	{
	}

	fwPlatformString(const std::string& arg)
		: std::string(arg)
	{
	}

	fwPlatformString(const char* arg)
		: std::string(arg)
	{
	}

	inline fwPlatformString(const wchar_t* wideString)
		: std::string(ConvertString(wideString))
	{

	}
};

typedef char pchar_t;

#define _pfopen fopen
#define _P(x) x
#endif

class STATIC InitFunctionBase
{
protected:
	InitFunctionBase* m_next;

	int m_order;

public:
	InitFunctionBase(int order = 0);

	virtual void Run() = 0;

	void Register();

	static void RunAll();
};

class STATIC InitFunction : public InitFunctionBase
{
private:
	void(*m_function)();

public:
	InitFunction(void(*function)(), int order = 0)
		: InitFunctionBase(order)
	{
		m_function = function;

		Register();
	}

	virtual void Run()
	{
		m_function();
	}
};