#include "leptjson.h"
#include <assert.h>	 /* assert() */
#include <stdlib.h>	 /* NULL, malloc(), realloc(), free(), strtod() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>	 /* HUGE_VAL */
#include <string.h>  /* memcoy() */

#ifndef TRUE
#define TRUE 1
#endif 

#ifndef FALSE
#define FALSE 0
#endif 

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)	do { assert(*c->json == (ch)); c->json ++; } while(0)
#define ISDIGIT(ch)     ((ch) >= '0' && (ch) <= '9')
#define PUTC(c, ch)     do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

#define STRING_ERROR(ret) do { c->top = head; return ret; } while (0)

/* 为减少解析函数之间传递多个参数 我们把需要传递的数据都放进结构体lept_context */
typedef struct {
	const char *json;
    /* a stack buffer, dymamically store bytes (string's length/memory size is not fixed)*/
    char *stack;
    size_t size, top;   
}lept_context;

/*
 c: stack, size: allocate memory size
 if stack memory is not enough, allocate more (1.5 times)
 return the start address of allocated memory
 void* can be converted to any other pointer type
*/
static void* lept_context_push(lept_context *c, size_t size) {
    void *ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0) {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);   /* when c->stack is NULL, realloc() is equal to malloc() */
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

/*
    simply decrase counter top to top - size 
*/
static void* lept_context_pop(lept_context *c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

/* JSON-text = ws value ws 
 ws 表示空格 lept_parse_whitespace()跳过空格 */
static void lept_parse_whitespace(lept_context *c) {
	const char *p = c->json;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		++ p;
	c->json = p;
}

#if 0 
static int lept_parse_null(lept_context *c, lept_value *v) {
	/* 查看当前4个字符是否依次为null */
	EXPECT(c, 'n');
	/* 因为\0 ！= null中的任意字符 并且||具有短路特性 所以不会越界 */
	if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 3;
	v->type = LEPT_NULL;
	return LEPT_PARSE_OK;
}
static int lept_parse_true(lept_context *c, lept_value *v) {
	EXPECT(c, 't');
	if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 3;
	v->type = LEPT_TRUE;
	return LEPT_PARSE_OK;
}

static int lept_parse_false(lept_context *c, lept_value *v) {
	EXPECT(c, 'f');
	if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e')
		return LEPT_PARSE_INVALID_VALUE;
	c->json += 4;
	v->type = LEPT_FALSE;
	return LEPT_PARSE_OK;
}
#endif

static int lept_parse_literal(lept_context *c, lept_value *v, const char *literal, lept_type type) {
	size_t i;
	
	EXPECT(c, *literal);
	++ literal;
	for (i = 0; literal[i]; ++ i) {
		if (c->json[i] != literal[i])
			return LEPT_PARSE_INVALID_VALUE;
	}
	c->json += i;
	v->type = type;
	return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context *c, lept_value *v) {
	char *end;
	/* validate number */
	const char *p = c->json;
	/* if negative, skip one char*/
	if (*p == '-')	
		++ p;
	/* integer */
	if (*p == '0') ++ p;
	else {
		if (!ISDIGIT(*p))	return LEPT_PARSE_INVALID_VALUE;
		++ p;
		while (ISDIGIT(*p))	++ p;
	}
	
	if (*p == '.') {
		++ p;
		if (ISDIGIT(*p))		
			while (ISDIGIT(*p))	++ p;	/* skip over all digit */
		else	/* there must be digit after '.' */
			return LEPT_PARSE_INVALID_VALUE;
	}	

	if (*p == 'E' || *p == 'e') {
		++ p;
		if (*p == '+' || *p == '-')
			++ p;
		if (!ISDIGIT(*p))	return LEPT_PARSE_INVALID_VALUE;
		while (ISDIGIT(*p))	++ p;
	}
	/* double strtod(const char *str, char **endptr): string to double,
		str: a pointer to string 
		endptr: a pointer to a pointer of type char, which will be set to the
			position of the first character that was not part of the number.
	  */	
	v->u.n = strtod(c->json, &end);
	
	if (errno == ERANGE) {
		errno = 0;
		if (v->u.n == HUGE_VAL || -v->u.n == HUGE_VAL)
			return LEPT_PARSE_NUMBER_TOO_BIG;
	}
	
	c->json = p;
	v->type = LEPT_NUMBER;
	return LEPT_PARSE_OK;	
}

/* the following 4 chars start with p is parsed as hex integer 
   the result value is store in *u
 */
static const char* lept_parse_hex4(const char *p, unsigned *u) {
   int i;   
   *u = 0;
   for (i = 0; i < 4; ++ i) {
       char ch = *p ++;
       *u <<= 4;  /* u = u * 16 */
       if (ISDIGIT(ch))                 *u |= ch - '0';
       else if (ch >= 'A' && ch <= 'F') *u |= ch - 'A' + 10;
       else if (ch >= 'a' && ch <= 'f') *u |= ch - 'a' + 10;
       else return NULL;     
   }
   return p;
}

static void lept_encode_utf8(lept_context *c, unsigned u) {
    if (u <= 0x7F)  /* one byte, same as ASCII*/
        PUTC(c, u & 0XFF);
    else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6)  & 0xFF));
        PUTC(c, 0x80 | (u         & 0x3F));
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    } else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

/*
 string start with \", end with \"
 process one char at a time, escape character is processed explictly
 \0 ?
 */
static int lept_parse_string(lept_context *c, lept_value *v) {
	unsigned u, u2;  /* unicode */
    size_t head = c->top, len;
	const char *p;
	EXPECT(c, '"');
	p = c->json;
	for (;;) {
		char ch = *p ++;
		switch (ch) {
			case '\"': 
				len = c->top - head;
                /* pop entire string once for all */
                lept_set_string(v, (const char*)lept_context_pop(c, len), len);
                c->json = p;
				return LEPT_PARSE_OK;
            /* \0 in json is invalid, null character in json is \u0000 */
			case '\0':
				c->top = head;
				return LEPT_PARSE_MISSING_QUOTATION_MARK;
		    case '\\':  /* escaped char, start with \ (\\ in JSON-encoded) */
                switch (*p ++) {
                    case '\"': PUTC(c, '\"'); break;  /* " is \\\" in JSON-encoded string --> \" in C string */
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c,  '/'); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':  /* Unicode */
                        if (!(p = lept_parse_hex4(p, &u)))
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        /* surrogate pair*/
                        if (u >= 0xD800 && u <= 0xDBFF) { 
                            if (*p ++ != '\\' || *p ++ != u)  /* start with /u, another unicode point */
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = lept_parse_hex4(p, &u2)))
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        c->top = head;
                        return LEPT_PARSE_INVALID_STRING_ESCAPE;
                }
                break;
            default:
                if ((unsigned char)ch < 0x20) {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_CHAR;  /* invalid unescaped charactar */
                }
				PUTC(c, ch);	
		}
	}
}

static int lept_parse_value(lept_context *c, lept_value *v) {
	/* 根据第一个非空字符判断JSON的type */
	switch (*c->json) {
		case 'n': 	return lept_parse_literal(c, v, "null", LEPT_NULL);		/* null */
		case 't': 	return lept_parse_literal(c, v, "true", LEPT_TRUE);		/* true */
		case 'f':	return lept_parse_literal(c, v, "false", LEPT_FALSE);
		default:	return lept_parse_number(c, v);	/* let parse_number test if there are invalid value */
		case '"': 	return lept_parse_string(c, v);	
		case '\0':  return LEPT_PARSE_EXPECT_VALUE;		/* no value */
	}
}

/* 非static 允许外部访问 作为接口 */
int lept_parse(lept_value *v, const char *json) {
	lept_context c;
	int ret;
	assert(v != NULL);
	c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
	lept_init(v);
    lept_parse_whitespace(&c);
	ret = lept_parse_value(&c, v);
	if (ret != LEPT_PARSE_OK)
		return ret;
	lept_parse_whitespace(&c);
	if (*c.json) {
		v->type = LEPT_NULL;
		return LEPT_PARSE_ROOT_NOT_SINGULAR;
	}
	
	assert(c.top == 0);
	free(c.stack);
	
	return LEPT_PARSE_OK;
}

void lept_free(lept_value *v) {
    assert(v != NULL);
    if (v->type == LEPT_STRING) {
        free(v->u.s.s);
    }
    v->type = LEPT_NULL;    /* avoid duplicate release  */
}

lept_type lept_get_type(const lept_value *v) {
	assert(v != NULL);
	return v->type;
}

int lept_get_boolean(const lept_value *v) {
   assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value *v, int b) {
    /* if v is string, free its allocated memory  */
    lept_free(v); 
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value *v) {
	assert(v != NULL && v->type == LEPT_NUMBER);
	return v->u.n;
}

void lept_set_number(lept_value *v, double n) {
    /*
    assert(v != NULL);      // when set, v can be NULL ?
    */
    lept_free(v); 
    v->type = LEPT_NUMBER;
    v->u.n = n;
}

const char* lept_get_string(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

/*
  the length of string is not fixed, we need dynamic locate memory, by malloc(), free().
  to set a string value, we need clear the allocated memory, malloc a new memory,
  copy value to memory, assin last char to '\0' (null-terminated string) 
*/
void lept_set_string(lept_value *v, const char *s, size_t len) {
    /* s is a string or an empty string */
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);   /* clear allocated memory */
    v->u.s.s = (char *)malloc(len + 1);   
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}
