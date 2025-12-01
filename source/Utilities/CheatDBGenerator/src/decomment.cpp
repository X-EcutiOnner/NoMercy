// Source: https://code.google.com/archive/p/cpp-decomment/ (The 3-Clause BSD)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <ctype.h>

typedef unsigned char uchar;
typedef unsigned long ulong;

const int LINESIZE=8192;

enum cpp_state_e {
	BLANK,				// space
	IDNAME,				// identifier or reserved-word
	PAREN,				// parenthesis. "[", "]", "{", "}", "(", ")"
	SEPARATOR,			// separator or char/string closer. ",", ";", "'", """
	OPERATOR,			// operator or others. "=", "==", "+", "+=", "++", ...
	CPP_COMMENT,		// C++ single comment. "//..."
	C_COMMENT,			// C comment block.    "/* ... */"
	STRING_CONSTANT,	// string constant. ""...""
	CHAR_CONSTANT,		// char constant.   "'...'"
	STRING_ESCAPE,		// after "\" in string constant.
	CHAR_ESCAPE,		// after "\" in char constant.
};

//........................................................................

/** -b: keep blank line */
bool gIsKeepBlankLine = false;

/** -i: keep indent spaces */
bool gIsKeepIndent = false;

/** -m: keep minimum space */
bool gIsKeepMinimumSpace = false;

/** -q: remove quoted string */
bool gIsRemoveQuotedString = false;

//------------------------------------------------------------------------
inline bool IsAlnum(int c)
{
	return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

inline bool IsIdNameChar(int c)
{
	return (c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

inline bool IsSpace(int c)
{
	return (c <= ' ');
}

inline bool IsParen(int c)
{
	return (c == '[' || c == ']' || c == '{' || c == '}' || c == '(' || c == ')');
}

inline bool IsUnaryOp(int c)
{
	return (c == '&' || c == '*' || c == '+' || c == '-' || c == '~' || c == '!');
}

bool IsAllSpaces(const char* s)
{
	while (*s) {
		if (!IsSpace(*s++))
			return false;
	}
	return true;
}

inline bool strequ(const char* s1, const char* s2)
{
	return strcmp(s1, s2) == 0;
}

//------------------------------------------------------------------------
void DecommentLine(const char* fname, int line, cpp_state_e& state, char* d, const char* s)
{
	int c;
	char* top = d;
	cpp_state_e lastToken = state;
	bool needSpace = false;
	bool isMacro = false;
	while ((c = (uchar)*s++) != '\0')
	{
		if (c == '\\' && *s == '\n')
		{
			if (state == CPP_COMMENT)
			{
				fprintf(stderr, "%s(%d) !!!warning: line-marge-mark '\\' at end of single comment. ignore it.\n", fname, line);
				state = BLANK;
			}
			else if (state == C_COMMENT)
			{
			}
			else
			{
				*d++ = static_cast<char>(c);	// c='\\'
			}

			++s;
			continue;
		}

		switch (state)
		{
		case C_COMMENT:
			if (c == '*' && *s == '/')
			{
				state = BLANK; ++s;
			}
			continue;

		case CPP_COMMENT:
			if (c == '\n') {
				state = BLANK;
			}
			continue;

		case STRING_CONSTANT:
			if (c == '"')
				state = SEPARATOR;
			else {
				if (c == '\\')
					state = STRING_ESCAPE;
				if (gIsRemoveQuotedString)
					continue; // skip output
			}
			break;

		case CHAR_CONSTANT:
			if (c == '\'')
				state = SEPARATOR;
			else if (c == '\\')
				state = CHAR_ESCAPE;
			break;

		case STRING_ESCAPE:
			state = STRING_CONSTANT;
			if (gIsRemoveQuotedString)
				continue; // skip output
			break;

		case CHAR_ESCAPE:
			state = CHAR_CONSTANT;
			break;

		case BLANK:
			if (c == '\n' || IsSpace(c))
				continue;
			if (c == '#') {
				isMacro = true;
			}
			if (isMacro && lastToken == IDNAME && (c == '"' || c == '\'' || c == '(' || IsUnaryOp(c)) && d > top) {
				// Don't remove a space after ID/if in following cases:
				//  #define ID "abc"
				//  #define ID 'c'
				//  #define ID (-1)
				//  #define ID -1
				//  #if -1
				needSpace = true;
			}
			if (gIsKeepMinimumSpace && d > top) {
				needSpace = true;
			}
parse_token:
			if (c == '/' && *s == '*') {
				state = C_COMMENT; ++s;
				continue;
			}
			else if (c == '/' && *s == '/') {
				state = CPP_COMMENT; ++s;
				continue;
			}
			else if (c == '"') {
				lastToken = state = STRING_CONSTANT;
				break;
			}
			else if (c == '\'') {
				lastToken = state = CHAR_CONSTANT;
				break;
			}
			else if (IsParen(c)) {
				lastToken = state = PAREN;
				break;
			}
			else if (c == ',' || c == ';') {
				lastToken = state = SEPARATOR;
				break;
			}
			else if (IsIdNameChar(c)) {
				if (lastToken == IDNAME && state == BLANK && d > top) {
					needSpace = true;
				}
				lastToken = state = IDNAME;
				break;
			}
			else {
				if (lastToken == OPERATOR && state == BLANK && d > top)
				{
					int c0 = (uchar) d[-1];
					if ((c0 == '/' && c == '*') || (c0 == '*' && c == '/')
							|| c0 == c  /* "+ +", "& &", ": ::", "> >"... */) {
						needSpace = true;
					}
				}
				lastToken = state = OPERATOR;
				break;
			}

		case PAREN:
		case SEPARATOR:
		case IDNAME:
		case OPERATOR:
			if (c == '\n' || IsSpace(c)) {
				state = BLANK;
				continue;
			}
			goto parse_token;
		}//.endswitch state
		if (needSpace) {
			*d++ = ' '; needSpace = false;
		}
		*d++ = static_cast<char>(c);
	}//.endwhile s

	*d = '\0';

	if (state == CPP_COMMENT)
		state = BLANK;
}


//------------------------------------------------------------------------
void DecommentFile(const char* fname, FILE* fin, FILE* fout)
{
	char buf[LINESIZE];
	char line[LINESIZE];
	cpp_state_e cppState = BLANK;

	for (int i = 0; fgets(buf, sizeof(buf), fin) != NULL; ++i)
	{
		char* s = buf;
		
		if (gIsKeepIndent)
		{
			while (*s == ' ' || *s == '\t')
				++s;
		}

		DecommentLine(fname, i+1, cppState, line, s);

		if (!gIsKeepBlankLine && IsAllSpaces(line))
			continue;

		if (buf < s)
			fwrite(buf, 1, s - buf, fout); // indent
		
		fputs(line, fout); // decommented line
		putc('\n', fout);
	}
}

FILE* OpenFile(const char* fname, const char* mode)
{
	FILE* fp = nullptr;
	errno_t err = fopen_s(&fp, fname, mode);
	if (err || fp == NULL) {
		fprintf(stderr, "can't open file: %s error: %d\n", fname, err);
		exit(EXIT_FAILURE);
	}
	return fp;
}

//------------------------------------------------------------------------
bool DecommentMain(const char* c_szInFile, const char* c_szOutFile)
{
	FILE* fin = OpenFile(c_szInFile, "r");
	if (!fin)
		return false;
	
	FILE* fout = OpenFile(c_szOutFile, "w");
	if (!fout)
	{
		fclose(fin);
		return false;
	}

	DecommentFile(c_szInFile, fin, fout);

	fclose(fin);
	fclose(fout);
	return true;
}
