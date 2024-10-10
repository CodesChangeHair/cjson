#include <stdio.h>
#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
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

#ifndef LEPT_PARSE_STRINGFY_INIT_SIZE
#define LEPT_PARSE_STRINGFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch)	do { assert(*c->json == (ch)); c->json ++; } while(0)
#define ISDIGIT(ch)     ((ch) >= '0' && (ch) <= '9')
#define PUTC(c, ch)     do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)


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

static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return LEPT_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

#if 0
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
#endif

static int lept_parse_number(lept_context *c, lept_value *v) {
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
        if (ISDIGIT(*p)) {
            ++ p;		
            while (ISDIGIT(*p))	++ p;	/* skip over all digit */
        }
        else	/* there must be digit after '.' */
            return LEPT_PARSE_INVALID_VALUE;
    }	

    if (*p == 'E' || *p == 'e') {
        ++ p;
        if (*p == '+' || *p == '-')
            ++ p;
        if (!ISDIGIT(*p))	return LEPT_PARSE_INVALID_VALUE;
        ++ p;
        while (ISDIGIT(*p))	++ p;
    }
    /* double strtod(const char *str, char **endptr): string to double,
str: a pointer to string 
endptr: a pointer to a pointer of type char, which will be set to the
position of the first character that was not part of the number.
     */	
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE) {
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
   \0 is invalid for JSON encoded string (\u00 is for null character)
 */

/* parse string, write result to str and len */

#define STRING_ERROR(ret) do { c->top = head; return ret; } while (0)

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
    size_t head = c->top;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                               if (!(p = lept_parse_hex4(p, &u)))
                                   STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                               if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                                   if (*p++ != '\\')
                                       STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                                   if (*p++ != 'u')
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
                               STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int lept_parse_string(lept_context *c, lept_value *v) {
    int ret;
    char *s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
        lept_set_string(v, s, len);
    return ret;
}

/* forward declare */
static int lept_parse_value(lept_context *c, lept_value *v);

static int lept_parse_array(lept_context *c, lept_value *v) {
    size_t size = 0, i;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    /* no element */
    if (*c->json == ']') {
        c->json ++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }
    /* 
       parse one element at a time, store the lept_value in stack buffer
       for , continue to parse; for ], pop all stored bytes, copy to arrary
     */
    for(;;) {
        lept_value e;  /* element in arrary */
        lept_init(&e);

        lept_parse_whitespace(c);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
            break;

        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size ++;

        lept_parse_whitespace(c);
        if (*c->json == ',')
            c->json ++;
        else if (*c->json == ']') {
            c->json ++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.a.e = (lept_value *)malloc(size), lept_context_pop(c, size), size);
            return  LEPT_PARSE_OK;
        } else {
            ret =  LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* ret != LEPT_PARSE_OK, break before pop out stack element*/
    /* Pop and free values on the stack */
    for (i = 0; i < size; i ++) {
        lept_free((lept_value *)lept_context_pop(c, sizeof(lept_value)));
    }
    return ret;
}

static int lept_parse_object(lept_context *c, lept_value *v) {
    size_t size, i;
    lept_member m, *pm;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json ++;
        v->type = LEPT_OBJECT;
        v->u.o.size = 0;
        v->u.o.m = NULL;
        return LEPT_PARSE_OK;
    }

    m.k = NULL;
    size = 0;
    for (;;) {
        char *str;
        lept_init(&m.v);
        lept_parse_whitespace(c);
        if (*c->json != '"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }

        if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK) {
            break;
        }
        memcpy(m.k = (char *)malloc(m.klen + 1), str, m.klen);
        m.k[m.klen] = '\0';

        lept_parse_whitespace(c);
        if (*c->json == ':') {
            c->json ++;
        } else {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }

        lept_parse_whitespace(c);
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            break;
        }

        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size ++;
        m.k = NULL; /* ownership is transferred to member on the stack */

        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json ++;
        } else if(*c->json == '}') {
            c->json ++;
            v->u.o.size = size;
            size *= sizeof(lept_member);
            memcpy(v->u.o.m = (lept_member*)malloc(size), lept_context_pop(c, size), size);
            v->type = LEPT_OBJECT;
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }

    free(m.k);
    for (i = 0; i < size; i ++) {
        pm = (lept_member *)lept_context_pop(c, size);
        free(pm->k);
        lept_free(&pm->v);
    }
    v->type = LEPT_NULL;
    return ret;
}

static int lept_parse_value(lept_context *c, lept_value *v) {
    /* 根据第一个非空字符判断JSON的type */
    switch (*c->json) {
        case 'n': 	return lept_parse_literal(c, v, "null", LEPT_NULL);		/* null */
        case 't': 	return lept_parse_literal(c, v, "true", LEPT_TRUE);		/* true */
        case 'f':	return lept_parse_literal(c, v, "false", LEPT_FALSE);
        default:	return lept_parse_number(c, v);	/* let parse_number test if there are invalid value */
        case '"': 	return lept_parse_string(c, v);	
        case '[':   return lept_parse_array(c, v);
        case '{':   return lept_parse_object(c, v);
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
    size_t i;
    assert(v != NULL);
    switch (v->type) {
        case LEPT_STRING:
            free(v->u.s.s);
            break;
        case LEPT_ARRAY:
            for (i = 0; i < v->u.a.size; i ++)
                lept_free(&v->u.a.e[i]);
            free(v->u.a.e);
            break;
        case LEPT_OBJECT:
            for (i = 0; i < v->u.o.size; i ++) {
                lept_free(&v->u.o.m[i].v);
                free(v->u.o.m[i].k);
            }
            free(v->u.o.m);
            break;
        default: break;
    }
    v->type = LEPT_NULL;
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

/* array */
size_t lept_get_array_size(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

lept_value* lept_get_array_element(const lept_value *v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

size_t lept_get_object_size(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

const char* lept_get_object_key(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

static void lept_stringify_value(lept_context *c, const lept_value *v);

char* lept_stringify(const lept_value *v, size_t *length) 
{
    lept_context c;
    assert(v != NULL);
    c.stack = (char*)malloc(c.size = LEPT_PARSE_STRINGFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length)
        *length = c.top;
    PUTC(&c, '\0');
    return c.stack;
}

#define PUTS(c, s, len) memcpy(lept_context_push(c, len), s, len)
static void lept_stringify_string(lept_context *c, const char *s, size_t len);

static void lept_stringify_value(lept_context *c, const lept_value *v) {
    size_t i;
    char *buffer;
    int length;
    switch(v->type) {
        case LEPT_NULL:  PUTS(c, "null", 4);  break;
        case LEPT_FALSE: PUTS(c, "false", 5); break;
        case LEPT_TRUE:  PUTS(c, "true", 4);  break;
        case LEPT_STRING:     lept_stringify_string(c, v->u.s.s, v->u.s.len); break;
        case LEPT_NUMBER:
                         buffer = lept_context_push(c, 32);
                         length = sprintf(buffer, "%.17g", v->u.n);
                         c->top -= 32 - length;
                         break;
        case LEPT_ARRAY:
                         PUTC(c, '[');
                         for (i = 0; i < v->u.a.size; i ++) {
                             lept_stringify_value(c, &v->u.a.e[i]);
                             if (i + 1 < v->u.a.size)
                                 PUTC(c, ',');
                         }
                         PUTC(c, ']');
                         break;
        case LEPT_OBJECT:
                         PUTC(c, '{');
                         for (i = 0; i < v->u.o.size; i ++) {
                             lept_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
                             PUTC(c, ':');
                             lept_stringify_value(c, &v->u.o.m[i].v);
                             if (i + 1 < v->u.o.size)
                                 PUTC(c, ',');
                         }
                         PUTC(c, '}');
                         break;
        default:    assert(0 && "invalid type");
    }
}


#if 0
static int lept_stringify_string(lept_context *c, const char *s, size_t len) {
    assert(s != NULL);
    size_t i;
    PUTC(c, '"');
    for (i = 0; i < len; ++ i) {
        unsigned char ch = (unsigned char)s[i];
        switch(ch) {
            case '\"':  PUTS(c, "\\\"", 2); break;
            case '\\':  PUTS(c, "\\\\", 2); break;
            case '\b':  PUTS(c, "\\b",  2); break;
            case '\f':  PUTS(c, "\\f",  2); break;
            case '\n':  PUTS(c, "\\n",  2); break;
            case '\r':  PUTS(c, "\\r",  2); break;
            case '\t':  PUTS(c, "\\t",  2); break;
            default:
                        if (ch < 0x20) {
                            char buffer[7];
                            sprintf(buffer, "\\u0x4X", ch);
                            PUTS(c, buffer, 6);
                        } 
                        else {
                            PUTC(c, s[i]);
                        }
        }
    }
    PUTC(c, '"');
}
#else
static void lept_stringify_string(lept_context *c, const char *s, size_t len) {
    static const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    size_t size, i;
    char *head, *p;
    assert(s != NULL);
    p = head = lept_context_push(c, size = len * 6 + 2);  /* a char may \u00xx */
    *p ++ = '"';
    for (i = 0; i < len; i ++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\"': *p ++ = '\\'; *p ++ = '\"'; break;
            case '\\': *p ++ = '\\'; *p ++ = '\\'; break;
            case '\b': *p ++ = '\\'; *p ++ = 'b';  break;
            case '\f': *p ++ = '\\'; *p ++ = 'f';  break;
            case '\n': *p ++ = '\\'; *p ++ = 'n';  break;
            case '\r': *p ++ = '\\'; *p ++ = 'r';  break;
            case '\t': *p ++ = '\\'; *p ++ = 't';  break;
            default:
                if (ch < 0x20) {
                    *p ++ = '\\'; *p ++ = 'u'; *p ++ = '0'; *p ++ = '0';
                    *p ++ = hex_digits[ch >> 4];
                    *p ++ = hex_digits[ch & 5];
                } 
                else
                    *p ++ = s[i];
        }
    }
    *p ++ = '"';
    c->top -= size - (p - head);
}
#endif
