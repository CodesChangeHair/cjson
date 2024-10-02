#ifndef LEPTJSON_H__	/* include guard, to prevent multiple inclusions of the same header file, by preprocess */
#define LEPTJSON_H__

#include <stddef.h>	/* size_t */

/* enum consists of a set of named integer constants. Each name in an enum corresponds to an integer value,starting from 0 by default unless explicitly assigned. */
typedef enum { LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT } lept_type;

/* typedef struct lept_value(any name) lept_value
create alias so when we define a new struct, we do not need to struct lept_value X */
/*
JSON最终时一个树状数据结构 目前需要解析null, true, false, number and string 
*/

/* forward declare, lept = struct lept_value, don't need to specify struct when define a structure */
typedef struct lept_value lept_value; 

struct lept_value {
	/*
      union is a user-defined data type similar to struct. but:
        shared memory: all members of a union share the same memory location
        size: the size of the union is equal to the size of its largest number, plus possible
            padding for alignment
        one active member: at any given memoment, only one member can store a meaningful value.
     */
	union {
        struct {lept_value *e; size_t size; }a; /* e: array, size: number of arrary elements */
		struct { char *s; size_t len; }s; /* s: null-terminated string, len: string length */
		double n;						  /* n: number */
	}u;
	lept_type type;	/* type is enum, a constant integer. For now, we only use it to represent null, true and false. */
}; 


/* Retruen value 表示解析结果 */
enum {
	LEPT_PARSE_OK = 0,					     /* string format is correct */
	LEPT_PARSE_EXPECT_VALUE,			     /* no value  */
	LEPT_PARSE_INVALID_VALUE,			     /* invalid format */
	LEPT_PARSE_ROOT_NOT_SINGULAR,		     /* extra chars */
	LEPT_PARSE_NUMBER_TOO_BIG, 			     /* number is too big for double */
	LEPT_PARSE_MISS_QUOTATION_MARK,	     /* string missing " */
	LEPT_PARSE_INVALID_STRING_ESCAPE,	     /* string invalid "\x" */
	LEPT_PARSE_INVALID_STRING_CHAR,		     /* string invalid char */
    LEPT_PARSE_INVALID_UNICODE_HEX,          /* unicode string, invalid hex value */
    LEPT_PARSE_INVALID_UNICODE_SURROGATE,    /* unicode string */
    LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET  /* arrary missing , or ] */
};

#define lept_init(v) do { (v)->type = LEPT_NULL; } while (0)

/* parse string(null-terminated string) to Json structure
User sent a C string and get a json type data i
提供给外部的API, 用户输入字符串 函数将其解析为JSON树状结构 存储在lept_value中
*/
int lept_parse(lept_value *v, const char *json);

void lept_free(lept_value *v);

/* get json value type */
lept_type lept_get_type(const lept_value *v);

#define lept_set_null(v)	lept_free(v)

/* boolean */
int lept_get_boolean(const lept_value *v);
void lept_set_boolean(lept_value *v, int b);

/* get number when json type is NUMBER */
double lept_get_number(const lept_value *v);
void lept_set_number(lept_value *v, double n);

/* string */
const char* lept_get_string(const lept_value *v);
size_t lept_get_string_length(const lept_value *v);
void lept_set_string(lept_value *v, const char *s, size_t len);

/* arrary */
size_t lept_get_array_size(const lept_value *v);

lept_value* lept_get_array_element(const lept_value *v, size_t index);

#endif  /* LEPTJSON_H__*/
